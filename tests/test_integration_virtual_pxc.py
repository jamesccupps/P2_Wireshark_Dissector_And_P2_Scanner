"""End to end: a peer's DBCHANGE notification arriving while a read is in flight.

The unit tests in `test_framing.py` pin the predicate. This pins the thing the
predicate exists for: a frame the scanner did not ask for, landing on the
socket it is waiting on, being named correctly and not disturbing the read.

The old predicate tested for a two-byte payload and so was never true, which is
why the notification was reported as "unmatched". No test caught it because the
scanner had no tests -- and the virtual PXC could not have emitted one to test
against, because its only outbound-push path was itself malformed (two
direction bytes, a constant msg_type). Both are fixed; this is what proves it.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PANEL_DIR = ROOT / "virtual_pxc"

if not (PANEL_DIR / "virtual_pxc.py").is_file():
    pytest.skip("virtual PXC not present in the repository",
                allow_module_level=True)
sys.path.insert(0, str(PANEL_DIR))

import virtual_pxc                                        # noqa: E402
import p2_scanner                                         # noqa: E402


@pytest.fixture()
def panel():
    p = virtual_pxc.VirtualPxc.from_fixtures(PANEL_DIR / "fixtures.json")
    p.start()
    try:
        yield p
    finally:
        p.stop()


@pytest.fixture()
def conn(panel):
    c = p2_scanner.P2Connection(panel.host, port=panel.port,
                                network=panel.bln, scanner_name="P2SCAN")
    assert c.connect(panel.node) is True
    try:
        yield c
    finally:
        c.close()


def test_a_dbchange_arriving_mid_read_is_named_and_harmless(panel, conn):
    seen = []
    conn.on_discarded_frame = lambda msg, reason: seen.append(reason)

    assert panel.push_dbchange(virtual_pxc.OP_DBCHANGE_POINT) == 1
    time.sleep(0.05)                       # let it land ahead of the request

    result = conn.read_point("VAV001", "ROOM TEMP", panel.node)

    assert seen == ["dbchange_notify"], (
        "the notification should be reported for what it is; got %r" % (seen,))
    assert result is not None, "the read must still complete"
    assert result["value"] == pytest.approx(72.5)


def test_the_panel_refuses_to_emit_an_unattested_notification(panel):
    """The fixture's whole value is that it will not teach a wrong frame."""
    with pytest.raises(ValueError):
        panel.push_dbchange(0x0952)        # a DBCHANGE opcode never observed


def test_a_push_frame_is_self_consistent(panel):
    """msg_type derived, one direction byte, opcode where a client looks.

    Built rather than sent, so the assertion is about the bytes and not about
    timing. The defect this replaces put TWO direction bytes on every push,
    which shifted the slots and turned the first two characters of the node
    name into the opcode.
    """
    import struct
    frame = panel._build_push_frame(struct.pack(">H",
                                                virtual_pxc.OP_DBCHANGE_PPCL))
    total_len, msg_type, _seq = struct.unpack(">III", frame[:12])
    payload = frame[12:]

    assert total_len == len(frame)
    assert payload[0] == virtual_pxc.DIR_REQUEST
    assert payload[1] != 0x00, "slot 0 must start immediately after direction"

    off, slots = 1, []
    for _ in range(4):
        z = payload.index(b"\x00", off)
        slots.append(payload[off:z].decode("ascii"))
        off = z + 1
    assert slots == [panel.bln, panel._default_supervisor_name(),
                     panel.bln, panel.node]
    assert msg_type == virtual_pxc.expected_msg_type(slots)
    assert struct.unpack_from(">H", payload, off)[0] == \
        virtual_pxc.OP_DBCHANGE_PPCL
    assert payload[off + 2:] == b"", "a DBCHANGE notification carries no body"
