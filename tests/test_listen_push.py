"""The push listener, which decoded and emitted nothing for one release.

`_parse_routing_header` returned the direction as a one-byte slice while the
listener compared it to an int, so `dir_byte == 0x00` was never true and the
whole decode block was unreachable. The failure was silent in the worst way:
the connection was accepted and logged, so an operator watching a quiet
building could not tell "no COV activity" from "the tool is dead".

The `0x05` and `0x01` arms were a second, independent defect -- nested inside
`if dir_byte == 0x00`, they could not run even with the type corrected.

Both are pinned here. The first two tests would each have caught the original
defect on its own; the third covers the branch that was dead twice over.
"""
from __future__ import annotations

import json
import socket
import struct
import threading
import time

import pytest

import p2_scanner as ps

BLN = "MYBLN"
PANEL = "PXC1"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _tlv(s: bytes) -> bytes:
    return b"\x01\x00" + bytes([len(s)]) + s


def _routing(direction: int = 0x00) -> bytes:
    names = b"".join(n.encode() + b"\x00" for n in (BLN, "DEST", BLN, PANEL))
    return bytes([direction]) + names, names


def _frame(body: bytes, direction: int = 0x00, seq: int = 4242) -> bytes:
    head, names = _routing(direction)
    payload = head + body
    msg_type = 13 + len(names)
    return struct.pack(">III", 12 + len(payload), msg_type, seq) + payload


def _cov_body(name: bytes = b"ROOM TEMP", value: float = 72.5) -> bytes:
    return (
        b"\x02\x74"                      # 0x0274 AP2_COV_ANNUNCIATE
        + struct.pack(">H", 1)           # one point
        + struct.pack(">H", 0)           # name_space
        + _tlv(name)
        + _tlv(b"")                      # empty suffix: a top-level point
        + struct.pack(">f", value)
        + bytes(10)                      # condition block
    )


def _listen_once(tmp_path, frame: bytes, duration: int = 4):
    """Run the listener on loopback, deliver one frame, return emitted events."""
    out = tmp_path / "events.jsonl"
    port = _free_port()
    t = threading.Thread(
        target=ps.listen_for_push_notifications,
        kwargs=dict(port=port, duration=duration, output_format="json",
                    output_file=str(out), ack_enabled=False,
                    bind_address="127.0.0.1"),
        daemon=True,
    )
    t.start()
    time.sleep(1.0)                      # let the bind settle
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    sock.sendall(frame)
    time.sleep(0.5)
    sock.close()
    t.join(timeout=duration + 6)
    if not out.exists():
        return []
    return [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]


def test_the_routing_header_direction_is_an_int_not_a_byte_slice():
    """The convention that broke: bytes never equal an int, so a one-byte slice
    silently disables every `dir_byte == 0x00` test downstream. analyze_pcap.py
    and the pcap reader in the scanner both use the int form."""
    head, _ = _routing(0x00)
    parsed = ps._parse_routing_header(head + _cov_body())
    assert parsed is not None
    direction, names, body = parsed
    assert isinstance(direction, int), "direction must be an int, not a bytes slice"
    assert direction == 0x00
    assert names[0] == BLN and names[3] == PANEL
    assert body[:2] == b"\x02\x74"


def test_a_well_formed_cov_push_is_emitted(tmp_path):
    """The whole point of the listener. Emitted nothing before the fix."""
    events = _listen_once(tmp_path, _frame(_cov_body()))
    assert events, "a well-formed COV push produced no event"
    ev = events[0]
    assert ev["event"] == "cov"
    assert ev["opcode"] == "0x0274"
    assert ev["src_node"] == PANEL
    assert ev["bln"] == BLN
    assert ev["device"] == "ROOM TEMP"
    assert ev["value"] == pytest.approx(72.5)


def test_an_error_response_is_reported_rather_than_silently_dropped(tmp_path):
    """dir=0x05 was nested inside `if dir_byte == 0x00`, so it was unreachable
    even once the type was corrected. A panel error must leave a record."""
    body = struct.pack(">H", 0x0009)     # a status code, not an opcode
    events = _listen_once(tmp_path, _frame(body, direction=0x05))
    assert events, "a dir=0x05 error response produced no event"
    assert events[0]["event"] == "error_response"
