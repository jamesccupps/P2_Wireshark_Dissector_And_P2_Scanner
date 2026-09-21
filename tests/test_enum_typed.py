"""The 0x0981 enumerate record, walked as a declared structure.

`AP2_Upl_All_Point_Response` is declared, and walking it beats the three-shape
heuristic on every axis measured over sixty real bodies: sixty walk cleanly,
the **point type** comes out (which the heuristic cannot see at all), one value
is recovered that the heuristic misses, and two units are corrected where the
heuristic read a neighbouring TLV. The heuristic stays as the fallback.

The bodies here are built by the virtual panel, which is the only structurally
faithful source of one that carries no site's point names.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PANEL_DIR = ROOT / "virtual_pxc"
if not (PANEL_DIR / "virtual_pxc.py").is_file():
    pytest.skip("virtual PXC not present in the repository",
                allow_module_level=True)
sys.path.insert(0, str(PANEL_DIR))

import virtual_pxc                                        # noqa: E402

from p2_scanner import P2Connection                       # noqa: E402

ROUTING = b"\x01" + b"BLN\x00" + b"NODE\x00" + b"BLN\x00" + b"SUP\x00"


def record(name="TEST PT", descr="A test point", value=72.5, units="DEG F"):
    body = virtual_pxc.VirtualPxc._enum_record_body(name, descr, value, units)
    conn = P2Connection.__new__(P2Connection)
    return conn._parse_enum_points_response(ROUTING + body)


def test_an_analog_point_is_typed_analog():
    r = record(units="DEG F")
    assert r["p2_type"] == "analog_ro"
    assert r["units"] == "DEG F"
    assert r["value"] == pytest.approx(72.5)


def test_a_digital_point_is_typed_DIGITAL_and_carries_no_units():
    """The defect this closes.

    Every panel-resident point used to be published as an analogInput. One in
    four is digital -- LDO 12 and LDI 4 of sixty real records -- and a digital
    point read as analog shows 0.0 and 1.0 where a supervisor expects inactive
    and active. `eng_units` lives under the ANALOG arm of the point structure
    (PROTOCOL.md 11.5.1), so a digital point has no units field at all.
    """
    r = record(value=1.0, units="")
    assert r["p2_type"] == "digital_ro"
    assert r["point_type"] in (1, 2)
    assert r["units"] == ""
    assert r["value"] == pytest.approx(1.0)


def test_the_point_type_is_the_enum_value_not_a_guess():
    analog = record(units="PSI")["point_type"]
    digital = record(value=0.0, units="")["point_type"]
    assert analog != digital
    import p2_data
    assert p2_data.POINT_TYPES[analog][0].startswith("LA")
    assert p2_data.POINT_TYPES[digital][0].startswith("LD")


def test_the_name_and_description_survive_the_walk():
    r = record(name="AHU1 SAT", descr="Supply air temperature")
    assert r["device"] == "AHU1 SAT"
    assert r["point"] == "AHU1 SAT"
    assert r["description"] == "Supply air temperature"


def test_a_body_that_will_not_walk_falls_back_rather_than_vanishing():
    """The heuristic is still there, and still returns a record.

    A title-only entry -- no value, no units -- walks to a field boundary and
    stops, which the typed path refuses on purpose: nothing in the corpus says
    what a half-walked record should yield.
    """
    r = record(name="ZZ.TITLE", descr="Section heading", value=None, units="")
    assert r is not None
    assert r["device"] == "ZZ.TITLE"
    assert r.get("point_type") is None       # the fallback cannot know it


def test_the_typed_path_is_skipped_when_the_walker_is_absent(monkeypatch):
    """The scanner must still run as a single file beside p2_data.py alone."""
    import p2_scanner
    monkeypatch.setattr(p2_scanner, "p2_body", None)
    r = record(units="DEG F")
    assert r is not None                     # heuristic still answers
    assert r.get("point_type") is None
    assert r["units"] == "DEG F"


def test_p2_type_refuses_a_code_the_vendor_table_does_not_hold():
    assert P2Connection._p2_type_for(None) is None
    assert P2Connection._p2_type_for(0xFF) is None
    assert P2Connection._p2_type_for(3) == "analog_ro"     # LAI
    assert P2Connection._p2_type_for(2) == "digital_ro"    # LDO
    assert P2Connection._p2_type_for(7) == "digital_ro"    # LOOAP, three states


def test_the_three_speed_types_are_digital_despite_having_no_default_enum():
    """LFMSSL/LFMSSP broke the "has a default enum => digital" heuristic.

    The vendor enum library defines no `-22`/`-23` default state text, so the
    heuristic classified a four-state motor-speed point as an analog value.
    PROTOCOL.md 11 lists both among the digital-only fast/slow/stop families
    and their ASDU structures carry a `state_text_table` like every other
    enumerated type.
    """
    for code in (22, 23):
        assert P2Connection._p2_type_for(code) == "digital_ro"
        assert P2Connection._n_states_for(code) == 4
    # and the heuristic still holds for the genuinely analog types
    for code in (3, 4, 11, 20, 24):
        assert P2Connection._p2_type_for(code) == "analog_ro"
        assert P2Connection._n_states_for(code) is None


@pytest.mark.parametrize("point_type,expected", [
    (1, 2),      # LDI    OFF / ON
    (2, 2),      # LDO    OFF / ON
    (3, None),   # LAI    analog, no enumeration
    (4, None),   # LAO
    (7, 3),      # LOOAP  OFF / ON / AUTO
    (13, 3),     # LOOAL  OFF / ON / AUTO
    (14, 3),     # LFSSL  STOP / SLOW / FAST
    (15, 3),     # LFSSP
    (21, 6),     # LENUM
    (22, 4),     # LFMSSL Fast / Medium / Slow / Stop -- no default enum
    (23, 4),     # LFMSSP Fast / Medium / Slow / Stop -- no default enum
])
def test_the_state_count_comes_from_the_vendor_enumeration(point_type, expected):
    """"digital" is a lossy word for seven of the point types.

    A binary object holds two states. These carry three, four or six, and the
    vendor's own model has multiStateInput/Output/Value for exactly that. None
    of the seven occurs anywhere in this corpus, so nothing maps them -- but a
    consumer can now see the count instead of watching AUTO read as ON.
    """
    assert P2Connection._n_states_for(point_type) == expected


def test_a_two_state_point_reports_its_count_in_the_record():
    r = record(value=1.0, units="")
    assert r["n_states"] == 2
    assert record(units="DEG F")["n_states"] is None
