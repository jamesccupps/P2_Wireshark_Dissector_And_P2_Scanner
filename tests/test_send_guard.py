"""The emit guard on `P2Connection._send_message` refuses what it should.

From 2.7.0 through 2.11.0 `_send_message` called
`check_emit_allowed(getattr(msg, "opcode", None))`. P2Message has never had an
`opcode` attribute, so the guard was asked about None on every frame and
permitted all of them -- the one send path it sat on was unguarded, and the
bridge sends through the same connection class. Found by an outside review,
2026-11-15, and reproduced before this fix: a 0x4636 frame reached the socket.

The coverage test next door checks what the nine raw paths put on the wire.
This one checks that the guarded path refuses, with nothing but a stand-in
socket: no panel, no network.
"""
from __future__ import annotations

import struct

import pytest

import p2_scanner as ps

SLOTS = b"\x00MYBLN\x00NODE1\x00MYBLN\x00P2SCAN\x00"

REFUSED = sorted(set(ps.EBLN_STALL_RISK) | set(ps.EBLN_WRITES)
                 | {op for op in ps.EBLN_DIAGNOSTIC_RANGE
                    if op not in ps.EBLN_READS})

PERMITTED = [ps.P2Message.OP_COV_ENABLE, 0x4640, 0x4634, 0x464C, 0x0100]


class _Socket:
    def __init__(self):
        self.sent: list[bytes] = []

    def sendall(self, data):
        self.sent.append(bytes(data))


def _connection():
    conn = ps.P2Connection.__new__(ps.P2Connection)
    conn.sock = _Socket()
    return conn


def _message(payload: bytes) -> ps.P2Message:
    return ps.P2Message(ps.P2Message.msg_type_for(payload), 1, payload)


def _request(opcode: int) -> ps.P2Message:
    return _message(SLOTS + struct.pack(">H", opcode) + b"\x00\x00")


def test_the_refused_set_is_not_empty():
    assert len(REFUSED) >= 5


@pytest.mark.parametrize("opcode", REFUSED, ids=hex)
def test_a_refused_opcode_never_reaches_the_socket(opcode):
    conn = _connection()
    with pytest.raises(PermissionError):
        conn._send_message(_request(opcode))
    assert conn.sock.sent == []


@pytest.mark.parametrize("opcode", PERMITTED, ids=hex)
def test_a_permitted_opcode_is_sent_unchanged(opcode):
    conn = _connection()
    msg = _request(opcode)
    assert conn._send_message(msg) is True
    assert conn.sock.sent == [msg.to_bytes()]


def test_a_request_with_no_opcode_is_refused():
    """Four slots and nothing after them: there is nothing to check."""
    conn = _connection()
    with pytest.raises(PermissionError):
        conn._send_message(_message(SLOTS))
    assert conn.sock.sent == []


def test_request_opcode_reads_past_slots_of_any_length():
    long_slots = b"\x00" + b"\x00".join([b"B" * 15, b"N" * 15, b"B" * 15,
                                            b"S" * 15]) + b"\x00"
    assert ps.P2Message.request_opcode(long_slots + b"\x46\x36") == 0x4636
    assert ps.P2Message.request_opcode(b"\x01" + SLOTS[1:]) is None
