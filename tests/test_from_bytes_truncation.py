"""`P2Message.from_bytes` trusted the header's total_len and sliced with it.

Python slicing truncates rather than raising, so a frame claiming 500 bytes
with 100 delivered yielded an 88-byte payload and no indication that anything
was missing. Nothing in-tree reached it: `_recv_message` buffers to exactly
total_len before calling. But p2_scanner is imported as a library -- the
BACnet bridge does it -- and there a short read became a quietly wrong
message rather than a refused one.
"""
from __future__ import annotations

import struct

import p2_scanner as ps


def _header(total_len: int, msg_type: int = 13, seq: int = 1) -> bytes:
    return struct.pack(">III", total_len, msg_type, seq)


def test_a_complete_frame_still_parses():
    payload = b"\x00SLOTS-AND-BODY"
    msg = ps.P2Message.from_bytes(_header(12 + len(payload)) + payload)
    assert msg is not None
    assert msg.payload == payload
    assert msg.sequence == 1


def test_a_short_frame_is_refused_not_truncated():
    """Header says 500 bytes; 100 arrive."""
    data = _header(500) + b"\x41" * 88
    assert len(data) == 100
    # Was: a P2Message with an 88-byte payload, indistinguishable from a whole one.
    assert ps.P2Message.from_bytes(data) is None


def test_a_total_len_below_the_header_is_refused():
    """total_len=5 made data[12:5] an empty payload, reported as a valid message."""
    assert ps.P2Message.from_bytes(_header(5) + b"\x00body") is None


def test_trailing_bytes_past_total_len_are_left_alone():
    """Two frames in one buffer is a legitimate caller, not a malformed frame."""
    payload = b"\x00FIRST"
    first = _header(12 + len(payload)) + payload
    msg = ps.P2Message.from_bytes(first + b"\xde\xad\xbe\xef")
    assert msg is not None and msg.payload == payload
