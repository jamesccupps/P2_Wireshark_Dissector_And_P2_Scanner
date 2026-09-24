"""Three raw-frame builders hard-coded `msg_type = 0x33`.

`msg_type` is `13 + the total bytes of the four routing slots` (PROTOCOL.md
6.2) -- a length, not a class byte -- and a panel drops a frame whose header
disagrees with its slots, silently and with nothing in a log. `p2_frame()`
exists to compute it, and its own docstring says every hand-built frame in the
file goes through it. Three did not:

    _heartbeat_sweep       one frame per candidate node name
    _cold_probe            one frame per candidate BLN x node pair
    the 0x010C follow-up   names learned from a previous response

0x33 is 51, so those frames were correct only when the four slots happened to
total 38 bytes. `_cold_probe` sweeps names of deliberately varied length --
node1, NODE10, BOILER, CHILLER -- so most of its probes were built wrong and
came back `rejected_silent`, which reads as "no panel there".

The virtual PXC enforces this rule; that is what it is for. These tests drive
the real builders against it.
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
import p2_scanner as ps                                   # noqa: E402


@pytest.fixture()
def panel():
    p = virtual_pxc.VirtualPxc.from_fixtures(PANEL_DIR / "fixtures.json")
    p.start()
    try:
        yield p
    finally:
        p.stop()


def _derived(payload: bytes) -> int:
    return ps.P2Message.msg_type_for(payload)


def test_the_builders_no_longer_agree_with_0x33_by_accident():
    """The arithmetic, independent of any panel.

    17 + 2*len(bln) + len(node) + len(scanner) == 51 only for particular name
    lengths, and cold discovery varies exactly those lengths.
    """
    def slots(bln, node, scanner):
        return (b"\x00" + bln.encode() + b"\x00" + node.encode() + b"\x00" +
                bln.encode() + b"\x00" + scanner.encode() + b"\x00" + b"\x46\x40")

    assert _derived(slots("MYBLN", "node1", "P2SCAN")) != 0x33
    assert _derived(slots("MYBLN", "CHILLER", "P2SCAN")) != 0x33
    # and they differ from each other, which is the point 0x33 could not express
    assert _derived(slots("MYBLN", "node1", "P2SCAN")) != \
           _derived(slots("MYBLN", "CHILLER", "P2SCAN"))


@pytest.mark.parametrize("node", ["node1", "NODE10", "BOILER", "CHILLER"])
def test_cold_probe_reaches_a_strict_panel_for_any_node_name(panel, node, monkeypatch):
    """Before the fix every one of these came back rejected_silent.

    `_cold_probe` takes a host and reads the module-global port, so the
    fixture's ephemeral port has to be put there. Without this the probe
    dials 5033, finds nothing, and the test passes on `port_closed` having
    proved nothing at all.
    """
    monkeypatch.setattr(ps, "P2_PORT", panel.port)
    before = panel.dropped_bad_msg_type
    out = ps._cold_probe(panel.host, panel.bln, "P2SCAN", node,
                         site=panel.site, timeout=2.0)
    assert out["verdict"] != "port_closed", "never reached the fixture"
    assert panel.dropped_bad_msg_type == before, \
        "panel dropped the frame: header disagreed with the slots"
    # The panel answers a heartbeat for a name it does not own too; what
    # matters here is that the frame was framed well enough to be read at all.
    assert out["verdict"] != "rejected_silent"


def test_the_panel_really_would_have_dropped_the_old_frame(panel):
    """Pin the fixture's enforcement, so this test cannot pass vacuously."""
    import socket
    import struct

    routing = (b"\x00" + panel.bln.encode() + b"\x00" + b"node1" + b"\x00" +
               panel.bln.encode() + b"\x00" + b"P2SCAN" + b"\x00")
    payload = routing + b"\x46\x40" + b"\x00" * 8
    assert _derived(payload) != 0x33

    before = panel.dropped_bad_msg_type
    s = socket.create_connection((panel.host, panel.port), timeout=2.0)
    try:
        s.sendall(struct.pack(">III", 12 + len(payload), 0x33, 1) + payload)
        s.settimeout(1.0)
        try:
            answer = s.recv(4096)
        except socket.timeout:
            answer = b""
    finally:
        s.close()

    assert answer == b""
    assert panel.dropped_bad_msg_type == before + 1


def test_no_frame_builder_hard_codes_a_msg_type():
    """The rule, enforced in code rather than in a comment.

    A P2 frame header is struct.pack('>III', total_len, msg_type, seq). If the
    second argument is a literal, someone has chosen msg_type instead of
    computing it -- which is how these three got there, and the reason
    `p2_frame()` exists. Responses built by echoing a request's msg_type are a
    separate case; finding 11 covers `_build_ack_response`.
    """
    import ast

    src = (ROOT / "p2_scanner.py").read_text(encoding="utf-8")
    offenders = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not (isinstance(fn, ast.Attribute) and fn.attr == "pack"):
            continue
        if not (node.args and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == ">III"):
            continue
        if len(node.args) >= 3 and isinstance(node.args[2], ast.Constant):
            offenders.append(node.lineno)

    assert offenders == [], (
        "msg_type is a literal at p2_scanner.py line(s) %s; it is 13 + the "
        "total bytes of the four routing slots, so it must come from "
        "p2_frame() or P2Message.msg_type_for()" % offenders)
