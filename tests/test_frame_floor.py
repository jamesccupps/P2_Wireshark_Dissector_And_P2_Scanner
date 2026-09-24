"""The two implementations disagreed about the smallest legal frame.

    p2.lua           total < 13    bare return
    p2_scanner.py    total_len < 12   (six separate places)

So a 12-byte header-only frame was accepted by the Python reader and refused
by the dissector, and neither number is the one PROTOCOL.md 6.1.1 gives:

    "13 header bytes plus four NUL terminators is 17, and a request adds two
     opcode bytes for 19, so any total_len below that cannot describe a valid
     frame and a reader that subtracts without checking will underflow."

A framing layer has not read the direction byte when it checks the length, so
17 is the floor it can enforce; 19 belongs to the request parser. Both readers
use 17 now, from one named constant each.

No frame in the corpus is affected -- the smallest well-formed one anywhere is
41 bytes -- so this is about two readers agreeing, not about traffic.
"""
from __future__ import annotations

import socket
import struct
import threading

import p2_scanner as ps


def test_the_floor_is_the_documented_one():
    assert ps.P2_MIN_FRAME_LEN == 17


def test_every_length_check_uses_the_constant():
    """Six places drifted to 12 because each carried its own literal."""
    import ast
    from pathlib import Path

    src = (Path(__file__).resolve().parent.parent / "p2_scanner.py").read_text(
        encoding="utf-8")
    bad = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.ops[0], ast.Lt):
            continue
        left, right = node.left, node.comparators[0]
        if not isinstance(left, ast.Name):
            continue
        if left.id not in ("total_len", "msg_len", "total"):
            continue
        if isinstance(right, ast.Constant):
            bad.append((node.lineno, left.id, right.value))

    assert bad == [], "frame-length floor written as a literal at %s" % bad


def test_a_header_only_frame_is_refused():
    """12 bytes: a header and nothing else. The old Python floor allowed it."""
    assert ps.P2Message.from_bytes(struct.pack(">III", 12, 13, 1)) is None


def test_a_frame_too_short_for_four_slots_is_refused():
    """13-16 bytes: a direction byte and fewer than four NUL terminators."""
    for total in (13, 14, 15, 16):
        data = struct.pack(">III", total, 13, 1) + b"\x00" * (total - 12)
        assert ps.P2Message.from_bytes(data) is None, "accepted total_len=%d" % total


def test_the_smallest_legal_frame_is_accepted():
    """17: direction byte plus four empty slots."""
    payload = b"\x00" + b"\x00" * 4
    msg = ps.P2Message.from_bytes(struct.pack(">III", 17, 17, 1) + payload)
    assert msg is not None
    assert msg.payload == payload


def test_the_socket_reader_uses_the_same_floor():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        try:
            conn, _ = srv.accept()
            with conn:
                conn.sendall(struct.pack(">III", 14, 13, 1) + b"\x00\x00")
                conn.recv(1)
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    sock = socket.create_connection(("127.0.0.1", srv.getsockname()[1]), timeout=2.0)
    try:
        assert ps._recv_one_frame(sock, overall_timeout=1.0) is None
    finally:
        sock.close()
