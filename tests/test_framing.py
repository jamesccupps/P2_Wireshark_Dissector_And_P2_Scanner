"""Frame invariants, and the DBCHANGE-notification predicate.

The defect these pin is what made the gap visible. `p2_scanner` carried a
predicate testing for a **two-byte payload** -- a 14-byte frame -- to
recognise five opcodes that are **48 bytes** on the wire. It was never once
true, so the frames it was written to name went on being reported as
"unmatched", and nothing noticed because the scanner had no tests at all.

No frame smaller than 46 bytes is attested anywhere in the capture corpus.

Slot names below are placeholders chosen to have the same lengths as the
observed ones, so the arithmetic reproduces the measured msg_type 46 and
total_len 48 without carrying any site's names.
"""
from __future__ import annotations

import struct

import pytest

from p2_scanner import P2Message, p2_frame

SLOTS = ("SITEBLN", "SUPERVISOR", "SITEBLN", "NODE1")     # 7, 10, 7, 5

OP_DBCHANGE_POINT = 0x0951
OP_POINT_READ = 0x0220


def request(opcode, slots=SLOTS, body=b""):
    """direction 0x00 + four NUL-terminated slots + u16 opcode + body."""
    return (b"\x00"
            + b"".join(s.encode("ascii") + b"\x00" for s in slots)
            + struct.pack(">H", opcode)
            + body)


def response(direction=0x01, slots=SLOTS, body=b""):
    """A reply carries no opcode field -- direction, slots, then body."""
    return (bytes([direction])
            + b"".join(s.encode("ascii") + b"\x00" for s in slots)
            + body)


# --------------------------------------------------------------- the shape

def test_dbchange_notification_is_an_ordinary_request():
    """48 bytes, msg_type 46, zero-length body -- as measured on the wire."""
    frame = p2_frame(request(OP_DBCHANGE_POINT), seq=5261394)
    total_len, msg_type, _seq = struct.unpack(">III", frame[:12])
    assert total_len == 48
    assert msg_type == 46
    assert len(frame) == total_len

    msg = P2Message.from_bytes(frame)
    assert msg.is_dbchange_notify is True
    assert msg.is_response is False
    # Everything after the opcode. There is none: the opcode is the whole
    # operation, which is what "zero-length body" means -- not a missing frame.
    assert msg.payload[P2Message.msg_type_for(msg.payload) - 12 + 2:] == b""


@pytest.mark.parametrize("opcode", sorted(P2Message.DBCHANGE_NOTIFY_OPCODES))
def test_every_dbchange_opcode_is_recognised(opcode):
    assert P2Message.from_bytes(
        p2_frame(request(opcode), seq=1)).is_dbchange_notify is True


def test_msg_type_tracks_the_slot_names_not_the_opcode():
    """msg_type is a length. Longer names, larger value -- 6.2."""
    short = P2Message.msg_type_for(request(OP_DBCHANGE_POINT,
                                           ("A", "B", "C", "D")))
    assert short == 13 + 4 * 2
    assert P2Message.msg_type_for(request(OP_DBCHANGE_POINT)) == 46


def test_to_bytes_derives_msg_type_and_ignores_the_parsed_one():
    """A frame built with our slots must not inherit a peer's header length."""
    msg = P2Message(msg_type=0x33, sequence=7,
                    payload=request(OP_DBCHANGE_POINT))
    _total, msg_type, _seq = struct.unpack(">III", msg.to_bytes()[:12])
    assert msg_type == 46


# ------------------------------------------------------- what is NOT one

def test_the_two_byte_payload_is_not_a_notification():
    """The frame the old predicate looked for.

    A bare opcode as the entire payload gives total_len 14. No such frame
    exists in the corpus -- the smallest anywhere is 46 -- and accepting one
    here would re-import the claim that this fix removed.
    """
    assert P2Message(msg_type=0, sequence=0,
                     payload=struct.pack(">H", OP_DBCHANGE_POINT)
                     ).is_dbchange_notify is False


def test_a_response_is_not_a_notification():
    """Even one whose body happens to contain the opcode's bytes.

    A reply has no opcode field at all, so reading two bytes at the opcode
    offset reads body content.
    """
    msg = P2Message(msg_type=0, sequence=0,
                    payload=response(body=struct.pack(">H",
                                                      OP_DBCHANGE_POINT)))
    assert msg.is_response is True
    assert msg.is_dbchange_notify is False


def test_another_opcode_is_not_a_notification():
    assert P2Message.from_bytes(
        p2_frame(request(OP_POINT_READ), seq=1)).is_dbchange_notify is False


def test_a_runt_does_not_raise():
    """A payload that cannot be framed is not a notification, and not a crash.

    `_recv_response` calls this on whatever arrives, including truncated
    reads, so the predicate has to answer rather than raise.
    """
    for payload in (b"", b"\x00", b"\x00SITEBLN", b"\x00A\x00B\x00C\x00D"):
        assert P2Message(0, 0, payload).is_dbchange_notify is False


def test_msg_type_for_refuses_an_unterminated_payload():
    """It raises rather than guessing -- the predicate catches that."""
    with pytest.raises(ValueError):
        P2Message.msg_type_for(b"\x00SITEBLN")
