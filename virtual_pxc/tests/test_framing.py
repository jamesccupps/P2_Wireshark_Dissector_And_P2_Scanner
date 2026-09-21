"""The mock must reject what a real panel rejects.

A test fixture that answers everything proves nothing. Before this file the mock
had three properties that made it unable to fail the defects it exists to catch:

  * it unpacked `msg_type` and never compared it to the routing slots, so a
    client hard-coding the field was answered -- the exact bug
    `P2_BACnet_Bridge` shipped;
  * it emitted an extra NUL between the direction byte and the first slot, and
    parsed from offset 2 to match, so slot 0 lost its first character against
    any real client and nothing noticed;
  * it answered an unknown opcode with a synthetic SUCCESS, so every
    unimplemented operation looked implemented.

These tests pin all three. They speak raw sockets rather than going through
`p2_scanner`, because the point is to send frames a correct client would never
send.
"""
from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent      # the virtual_pxc/ package
sys.path.insert(0, str(HERE))

import virtual_pxc  # noqa: E402


@pytest.fixture()
def panel():
    m = virtual_pxc.VirtualPxc.from_fixtures(HERE / "fixtures.json")
    m.start()
    try:
        yield m
    finally:
        m.stop()


def _routing(bln: str, dest: str, scanner: str) -> bytes:
    """Direction byte + the four NUL-terminated slots. No leading NUL."""
    return (b"\x00"
            + bln.encode() + b"\x00"
            + dest.encode() + b"\x00"
            + bln.encode() + b"\x00"
            + scanner.encode() + b"\x00")


def _ask(panel, msg_type: int, opcode: int = 0x4640,
         scanner: str = "P2BRIDGE", timeout: float = 2.0):
    """Send one framed request; return the response bytes, or b'' on silence."""
    payload = _routing(panel.bln, panel.node.lower(), scanner) + struct.pack(">H", opcode)
    frame = struct.pack(">III", 12 + len(payload), msg_type, 1) + payload
    s = socket.create_connection((panel.host, panel.port), timeout=timeout)
    try:
        s.sendall(frame)
        s.settimeout(timeout)
        try:
            return s.recv(4096)
        except socket.timeout:
            return b""
    finally:
        s.close()


def _correct_msg_type(panel, scanner="P2BRIDGE") -> int:
    slots = [panel.bln, panel.node.lower(), panel.bln, scanner]
    return virtual_pxc.expected_msg_type(slots)


# ----------------------------------------------------------------- framing

def test_a_correct_header_length_is_answered(panel):
    resp = _ask(panel, _correct_msg_type(panel))
    assert resp, "panel did not answer a correctly framed request"
    assert panel.dropped_bad_msg_type == 0


@pytest.mark.parametrize("wrong", [0x33, 0x34, 0, 51, 52, 255])
def test_a_wrong_header_length_is_dropped_silently(panel, wrong):
    """The failure mode is silence, not an error. That is what makes it nasty.

    0x33 and 0x34 are in the list deliberately: they are the two values the
    withdrawn "dialect" model told implementers to choose between, and a client
    carrying that model sends one of them whatever its own node names are.
    """
    correct = _correct_msg_type(panel)
    if wrong == correct:
        pytest.skip("fixture names happen to produce this value")
    resp = _ask(panel, wrong)
    assert resp == b"", f"panel answered a frame with msg_type={wrong}"
    assert panel.dropped_bad_msg_type == 1


def test_the_two_dialect_values_are_not_special(panel):
    """Neither 0x33 nor 0x34 is privileged; only arithmetic decides."""
    assert _correct_msg_type(panel) not in (0x33, 0x34), (
        "fixture names coincidentally produce a legacy dialect value; "
        "choose different names so this test means something")
    assert _ask(panel, 0x33) == b""
    assert _ask(panel, 0x34) == b""


def test_relaxed_mode_still_answers_a_bad_header(panel):
    """`strict_framing=False` reproduces the old fixture, for comparison."""
    panel.strict_framing = False
    assert _ask(panel, 0x33) != b""


# ----------------------------------------------------------------- routing

def test_slot_zero_survives_the_round_trip(panel):
    """The phantom-NUL regression: `MYBLN` used to arrive as `YBLN`."""
    scanner = "P2BRIDGE"
    resp = _ask(panel, _correct_msg_type(panel, scanner), scanner=scanner)
    assert resp
    payload = resp[12:]
    slots = payload[1:].split(b"\x00")[:4]
    assert slots[0].decode() == panel.bln, (
        f"slot 0 came back as {slots[0]!r}, expected {panel.bln!r}")
    assert slots[1].decode() == scanner
    assert slots[3].decode() == panel.node


def test_the_response_header_length_matches_its_own_slots(panel):
    """The response's slots are role-swapped, so it must recompute, not echo."""
    resp = _ask(panel, _correct_msg_type(panel))
    assert resp
    _total, msg_type, _seq = struct.unpack(">III", resp[:12])
    slots = [s.decode() for s in resp[12:][1:].split(b"\x00")[:4]]
    assert msg_type == virtual_pxc.expected_msg_type(slots)


# ----------------------------------------------------------------- opcodes

def test_an_unknown_opcode_gets_not_found_not_a_fake_success(panel):
    resp = _ask(panel, _correct_msg_type(panel), opcode=0xBEEF)
    assert resp, "expected an error response, got silence"
    direction = resp[12]
    assert direction == virtual_pxc.DIR_ERROR, (
        f"unknown opcode answered with direction 0x{direction:02X}; "
        "a synthetic success is how an unimplemented operation looks done")
    assert panel.unknown_opcodes.get(0xBEEF) == 1


# ------------------------------------------------- 0x010D capability document

def test_services_rendered_returns_the_capability_document(panel):
    """0x010D AP2_SERVICES_RENDERED answers with an XML capability document.

    Content is modelled on 55 real documents recovered from stored panel
    databases (PROTOCOL.md 16.4.1); the framing is inferred, because this
    exchange appears in none of the 229 captures in the corpus.
    """
    resp = _ask(panel, _correct_msg_type(panel), opcode=0x010D)
    assert resp, "panel did not answer 0x010D"
    assert b"<ServicesRendered>" in resp
    assert b"<PanelBasics>" in resp
    assert panel.node.encode() in resp


def test_services_rendered_declares_island_bus_on_lan_zero(panel):
    """LAN 0 is the TX-I/O island bus; the P1 trunks are LANs 1-3.

    This is the off-by-one a client walking FLN addresses will hit if it
    assumes zero-based trunk numbering, and the wire corpus agrees: the `lan`
    field carries 1, 2 and 3 across 983 observations and never 0.
    """
    resp = _ask(panel, _correct_msg_type(panel), opcode=0x010D)
    assert b'<FLN LAN="0">ISLANDBUS</FLN>' in resp
    for lan in (1, 2, 3):
        assert ('<FLN LAN="%d">P1</FLN>' % lan).encode() in resp
    assert b'<FLN LAN="0">P1</FLN>' not in resp


def test_services_rendered_carries_more_than_the_vendor_template(panel):
    """The vendor template shows three <Services> elements; real panels carry
    eighteen. A client must parse an open set."""
    resp = _ask(panel, _correct_msg_type(panel), opcode=0x010D)
    for el in (b"OperatorActivityLogging", b"AlarmBuffer", b"FLNTopology",
               b"LicenseManager", b"TXIO", b"TrendDST", b"Adapt", b"usbTool"):
        assert el in resp, "missing <Services> element %r" % el
