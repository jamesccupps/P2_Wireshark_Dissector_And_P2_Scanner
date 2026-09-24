"""`_recv_one_frame`'s `overall_timeout` was a per-recv timeout, not a deadline.

`sock.settimeout(overall_timeout)` bounds one `recv`, and the function calls
`recv` in a loop. A peer that dribbles one byte just inside the interval keeps
the loop alive for as long as it cares to, so the parameter promised a bound it
did not provide. Every raw-socket call site passes 3.0 and assumes it means
three seconds.

Nothing here touches a panel. A loopback socket plays a slow, then a prompt,
peer.
"""
from __future__ import annotations

import socket
import struct
import threading
import time

import p2_scanner as ps

DEADLINE = 0.4          # what we ask _recv_one_frame for
DRIBBLE = 0.1           # peer's gap between bytes -- comfortably inside it
FRAME_LEN = 64          # 60 bytes after the prefix = 6.0 s of dribbling


def _serve(sender):
    """Run `sender(conn)` on one loopback connection; return the bound port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        try:
            conn, _ = srv.accept()
            with conn:
                sender(conn)
        except OSError:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv.getsockname()[1], t


def _dribbler(conn):
    frame = struct.pack(">I", FRAME_LEN) + b"\x00" * (FRAME_LEN - 4)
    conn.sendall(frame[:4])
    for b in frame[4:]:
        time.sleep(DRIBBLE)
        try:
            conn.sendall(bytes([b]))
        except OSError:
            return          # client hung up at the deadline, which is the point


def test_dribbling_peer_cannot_outlast_the_deadline():
    port, _ = _serve(_dribbler)
    sock = socket.create_connection(("127.0.0.1", port))
    try:
        t0 = time.monotonic()
        data = ps._recv_one_frame(sock, overall_timeout=DEADLINE)
        elapsed = time.monotonic() - t0
    finally:
        sock.close()

    assert data is None
    # The peer needs 6.0 s to finish. Before the fix every byte reset a 0.4 s
    # per-recv timeout and the call ran to completion.
    assert elapsed < 2.5, "took %.2fs; deadline is not being enforced" % elapsed


def test_a_prompt_frame_still_arrives_whole():
    payload = b"\x00" + b"PAYLOAD" * 4
    frame = struct.pack(">III", 12 + len(payload), 13, 7) + payload

    port, _ = _serve(lambda c: c.sendall(frame))
    sock = socket.create_connection(("127.0.0.1", port))
    try:
        data = ps._recv_one_frame(sock, overall_timeout=DEADLINE)
    finally:
        sock.close()

    assert data == frame


def test_the_socket_timeout_is_not_left_at_the_deadline_remainder():
    """enumerate_fln_devices reuses one socket across iterations.

    Draining the deadline and leaving the remainder on the socket would make
    the next sendall on that socket time out immediately.
    """
    port, _ = _serve(_dribbler)
    sock = socket.create_connection(("127.0.0.1", port))
    try:
        assert ps._recv_one_frame(sock, overall_timeout=DEADLINE) is None
        assert sock.gettimeout() == DEADLINE
    finally:
        sock.close()
