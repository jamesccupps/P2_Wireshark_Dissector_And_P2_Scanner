"""`discover_devices_on_node` survives a reply it cannot use.

Two defects, found by an outside review on 2026-11-15:

* The APPLICATION value was converted with `int()`, which raises on a NaN or an
  infinity. Nothing caught it, so one such reply ended discovery for every node
  still to come in a sweep.
* A batch's replies were collected until the peer paused for 0.3 s, with no cap
  on bytes or time. A peer that never paused grew the buffer without limit; one
  that kept a byte arriving inside each 0.3 s held the scan indefinitely.

A loopback socket plays the peer. Nothing here touches a panel.
"""
from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

import p2_scanner as ps


def _frame(seq: int, value: bytes) -> bytes:
    """A success response whose 3F FF FF block carries `value` as APPLICATION."""
    body = b"\x01" + b"\x00" * 50 + b"\x3f\xff\xff" + b"\x00" * 4 + value
    return struct.pack(">III", 12 + len(body), 0x33, seq) + body


class _Peer:
    """Accept one connection, read the batch, then run `behavior(conn, stop)`."""

    def __init__(self, behavior):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, args=(behavior,),
                                       daemon=True)
        self.thread.start()

    def _run(self, behavior):
        conn, _ = self.srv.accept()
        try:
            conn.settimeout(5)
            got = b""
            while b"APPLICATION" not in got:        # handshake, then the batch
                chunk = conn.recv(65536)
                if not chunk:
                    return
                got += chunk
            behavior(conn, self.stop)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=10)
        self.srv.close()


@pytest.fixture()
def run(monkeypatch):
    peers = []

    def _run(behavior):
        peer = _Peer(behavior)
        peers.append(peer)
        monkeypatch.setattr(ps, "P2_PORT", peer.port)
        monkeypatch.setattr(ps, "P2_NETWORK", "MYBLN")
        monkeypatch.setattr(ps, "P2_SITE", "BUILDING1")
        monkeypatch.setattr(ps, "_send_handshake",
                            lambda sock, frame, host=None: sock.sendall(frame) or True)
        t = time.monotonic()
        found = ps.discover_devices_on_node("127.0.0.1", "NODE1",
                                            device_list=["VAV001"],
                                            use_enumerate=False)
        return found, time.monotonic() - t

    yield _run
    for peer in peers:
        peer.close()


@pytest.mark.parametrize("value", [b"\x7f\xc0\x00\x00", b"\x7f\x80\x00\x00",
                                   b"\xff\x80\x00\x00"],
                         ids=["nan", "inf", "-inf"])
def test_a_non_finite_application_is_recorded_not_raised(run, value):
    def answer(conn, stop):
        conn.sendall(_frame(5000, value))
        stop.wait(2)

    found, _ = run(answer)
    assert found == [{"device": "VAV001", "application": 0, "description": ""}]


def test_a_finite_application_is_unchanged(run):
    def answer(conn, stop):
        conn.sendall(_frame(5000, struct.pack(">f", 2021.0)))
        stop.wait(2)

    found, _ = run(answer)
    assert [d["application"] for d in found] == [2021]


def test_a_peer_that_never_pauses_is_cut_off_by_size(run, monkeypatch):
    monkeypatch.setattr(ps, "DISCOVERY_BATCH_REPLY_CAP", 64 * 1024,
                        raising=False)

    def flood(conn, stop):
        give_up = time.monotonic() + 8
        while not stop.is_set() and time.monotonic() < give_up:
            conn.sendall(b"\x00" * 4096)

    _, elapsed = run(flood)
    assert elapsed < 4, "collected for %.1f s" % elapsed


def test_a_peer_that_trickles_is_cut_off_by_time(run, monkeypatch):
    monkeypatch.setattr(ps, "DISCOVERY_BATCH_REPLY_SECONDS", 1.0, raising=False)

    def trickle(conn, stop):
        give_up = time.monotonic() + 8
        while not stop.is_set() and time.monotonic() < give_up:
            conn.sendall(b"\x00")
            time.sleep(0.1)                   # well inside the 0.3 s gap

    _, elapsed = run(trickle)
    assert elapsed < 4, "collected for %.1f s" % elapsed
