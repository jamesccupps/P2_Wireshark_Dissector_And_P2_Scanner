"""`_recv_one_frame` read 4096 bytes to get a 4-byte length prefix.

Whatever came in behind the frame was read into the buffer and then thrown
away by the closing `buf[:total_len]` slice. Panels push unsolicited
AP2_DBCHANGE notifications on an already-open session -- the virtual PXC
models exactly that with `push_dbchange()` -- and `enumerate_fln_devices`
calls `_recv_one_frame` in a loop on one socket, so a piggybacked frame did
not merely go missing: the next iteration started reading mid-frame.

`P2Connection._recv_message` on the other receive path never had this problem;
it keeps a persistent `self._recv_buffer`. The two paths disagreed about a
case one of them handled correctly.

Nothing here touches a panel. A loopback socket sends two frames in one write.
"""
from __future__ import annotations

import socket
import struct
import threading

import p2_scanner as ps


def _frame(seq: int, body: bytes) -> bytes:
    payload = b"\x00" + body
    return struct.pack(">III", 12 + len(payload), 13, seq) + payload


FIRST = _frame(1, b"RESPONSE")
SECOND = _frame(2, b"DBCHANGE-PUSH")


def _serve_both_at_once():
    """One sendall carrying both frames, so they land in one recv."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        try:
            conn, _ = srv.accept()
            with conn:
                conn.sendall(FIRST + SECOND)
                conn.recv(1)        # hold the connection until the client leaves
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


def test_a_piggybacked_frame_survives_to_the_next_call():
    sock = socket.create_connection(("127.0.0.1", _serve_both_at_once()))
    try:
        first = ps._recv_one_frame(sock, overall_timeout=2.0)
        second = ps._recv_one_frame(sock, overall_timeout=2.0)
    finally:
        sock.close()

    assert first == FIRST
    # Before the fix the 4096-byte prefix read swallowed SECOND and dropped it,
    # so this call found an empty stream and timed out.
    assert second == SECOND
