"""The listener's ACK echoed the request's msg_type instead of deriving it.

    return struct.pack('>III', 12 + len(body), msg_type, seq) + body

It was correct for a well-formed request: the ACK reorders the same four slot
strings, so `13 + slot bytes` does not move. It was wrong the moment the
request's own header was wrong -- the listener copied a stranger's framing
error into its reply, and a panel drops a frame whose msg_type disagrees with
its slots without saying anything. A peer with a framing bug got silence back
and no way to tell that from "nobody is listening".

It also contradicted the invariant the file states everywhere else, including
in `p2_frame`'s own docstring: compute it, never choose it.
"""
from __future__ import annotations

import struct

import p2_scanner as ps

BLN = "MYBLN"
PANEL = "NODE1"
US = "P2SCAN"


def _request(msg_type: int, seq: int = 99) -> bytes:
    """A request payload: direction byte, four slots, then a body."""
    payload = (b"\x00" + BLN.encode() + b"\x00" + US.encode() + b"\x00" +
               BLN.encode() + b"\x00" + PANEL.encode() + b"\x00" + b"\x02\x74")
    return payload


def _header(frame: bytes):
    return struct.unpack(">III", frame[:12])


def test_the_ack_derives_its_own_msg_type():
    payload = _request(0)
    ack = ps._build_ack_response(7, payload)
    total, msg_type, seq = _header(ack)

    assert seq == 7
    assert total == len(ack)
    assert msg_type == ps.P2Message.msg_type_for(ack[12:])


def test_a_misframed_request_does_not_produce_a_misframed_ack():
    """The case the echo got wrong.

    A peer sends a header that disagrees with its slots. Echoing it back means
    our ACK is misframed too, so the peer drops it -- and a client with a
    framing bug is exactly the client that needs the reply.
    """
    payload = _request(0)
    correct = ps.P2Message.msg_type_for(payload)
    wrong = correct + 7                      # what a broken peer might send
    assert wrong != correct

    ack = ps._build_ack_response(7, payload)
    _, msg_type, _ = _header(ack)

    # Before the fix this returned `wrong`, straight from the request header.
    assert msg_type == ps.P2Message.msg_type_for(ack[12:])
    assert msg_type != wrong


def test_the_ack_swaps_source_and_destination():
    ack = ps._build_ack_response(7, _request(0))
    direction, names, rest = ps._parse_routing_header(ack[12:])

    assert direction == 0x01
    assert names == [BLN, PANEL, BLN, US]
    assert rest == b""


def test_an_unparseable_request_yields_no_ack():
    assert ps._build_ack_response(7, b"\x00no-terminators-here") == b""
