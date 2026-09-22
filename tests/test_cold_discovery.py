"""`_cold_status_query_probe`, whose success path raised NameError.

`msg_type` was a leftover from a probe loop over 0x33/0x34 that was removed;
the loop went, the reference stayed, and it was bound nowhere. Every failure
branch returns before reaching the offending line, so the function only ever
appeared to work -- a probe that got a real answer from a real panel crashed,
and one that got nothing returned None like normal. Neither caller catches
NameError.

Nothing here touches a panel. A loopback socket plays the panel and answers
one StatusQuery.
"""
from __future__ import annotations

import socket
import struct
import threading

import pytest

import p2_scanner as ps

BLN = "MYBLN"
PANEL = "PXC1"
US = "DCC-SVR|5033"
SUPERVISOR = "REALSVR|5033"


def _tlv(s: str) -> bytes:
    b = s.encode("ascii")
    return b"\x01" + struct.pack(">H", len(b)) + b


def _panel_response(seq: int) -> bytes:
    """A role-swapped StatusQuery answer: BLN in slot 0, node name in slot 3."""
    names = b"".join(n.encode() + b"\x00" for n in (BLN, US, BLN, PANEL))
    body = _tlv("SYST") + _tlv(SUPERVISOR)
    payload = b"\x00" + names + body
    msg_type = 13 + len(names)
    return struct.pack(">III", 12 + len(payload), msg_type, seq) + payload


@pytest.fixture()
def fake_panel(monkeypatch):
    """Answer exactly one StatusQuery on loopback, then stop."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    srv.settimeout(10)
    monkeypatch.setattr(ps, "P2_PORT", port)

    def serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            req = conn.recv(4096)
            seq = struct.unpack(">I", req[8:12])[0] if len(req) >= 12 else 0
            conn.sendall(_panel_response(seq))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port
    try:
        srv.close()
    except OSError:
        pass
    t.join(timeout=5)


def test_a_successful_status_query_returns_the_panel_identity(fake_panel):
    """The defect's whole shape: this raised NameError before the fix, and only
    on the path where the panel actually answered."""
    result = ps._cold_status_query_probe("127.0.0.1", "P2SCAN|5033", timeout=5.0)
    assert result is not None, "a well-formed panel answer produced no result"
    assert result["bln"] == BLN
    assert result["panel"] == PANEL
    assert result["supervisor"] == SUPERVISOR


def test_the_returned_msg_type_is_the_responses_own_header_field(fake_panel):
    """The docstring promises {'msg_type': int}. It must be the value the panel
    put on the wire, not a leftover name -- header length, PROTOCOL.md 6.2."""
    result = ps._cold_status_query_probe("127.0.0.1", "P2SCAN|5033", timeout=5.0)
    assert result is not None
    expected = 13 + len(b"".join(n.encode() + b"\x00" for n in (BLN, US, BLN, PANEL)))
    assert isinstance(result["msg_type"], int)
    assert result["msg_type"] == expected
