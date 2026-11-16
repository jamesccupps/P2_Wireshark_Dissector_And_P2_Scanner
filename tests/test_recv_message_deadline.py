"""`P2Connection._recv_message` bounds the whole frame, not each recv.

The socket timeout (READ_TIMEOUT) was applied per recv. A peer that sent one
byte just inside it kept the read open for as long as it cared to: 24 s with a
1 s timeout, measured by an outside review on 2026-11-15 and again here before
the fix. `_recv_one_frame` was given a deadline in 2.11.0 (test_recv_deadline.py);
this is the same defect on the connection class's own path.

A socketpair plays the peer. Nothing here touches a panel.
"""
from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

import p2_scanner as ps

TIMEOUT = 1.0
FRAME_LEN = 40          # 28 bytes after the header = 7 s of trickling at 0.25 s


@pytest.fixture()
def pair():
    a, b = socket.socketpair()
    a.settimeout(TIMEOUT)
    conn = ps.P2Connection.__new__(ps.P2Connection)
    conn.sock = a
    conn._recv_buffer = b""
    yield conn, b
    a.close()
    b.close()


def test_a_trickling_peer_is_cut_off_at_the_timeout(pair):
    conn, peer = pair
    stop = threading.Event()

    def trickle():
        peer.sendall(struct.pack(">I", FRAME_LEN) + b"\x00" * 8)
        for _ in range(FRAME_LEN - 12):
            if stop.wait(0.25):              # each byte well inside the timeout
                return
            try:
                peer.sendall(b"\x00")
            except OSError:
                return

    t = threading.Thread(target=trickle, daemon=True)
    t.start()
    started = time.monotonic()
    try:
        assert conn._recv_message() is None
        elapsed = time.monotonic() - started
    finally:
        stop.set()
        t.join(timeout=5)
    assert elapsed < TIMEOUT + 0.75, "held the read for %.1f s" % elapsed
    assert conn.sock.gettimeout() == TIMEOUT, "the socket's timeout was not restored"


def test_a_prompt_frame_is_returned_whole(pair):
    conn, peer = pair
    payload = b"\x01MYBLN\x00NODE1\x00MYBLN\x00P2SCAN\x00" + b"\x00\x00\x00\x00"
    sent = ps.P2Message(ps.P2Message.msg_type_for(payload), 77, payload)
    peer.sendall(sent.to_bytes())

    got = conn._recv_message()
    assert got is not None
    assert (got.sequence, got.payload) == (77, payload)
    assert conn.sock.gettimeout() == TIMEOUT
