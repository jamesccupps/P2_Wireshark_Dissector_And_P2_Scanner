"""`check_emit_allowed` sees 1 of the 10 send paths, and says so.

    "Coverage, stated honestly: a few standalone helpers (handshake, cold
     discovery) build raw frames and call sock.sendall directly, bypassing
     this check. Audited at the time of writing -- the only EBLN opcodes any
     of them emit are 0x4634 REPL_PULL and 0x4640 PING, both permitted."

The docstring is accurate. It is also a point-in-time human claim with nothing
behind it, and this session changed three of those raw paths, so "at the time
of writing" has already moved once. CLAUDE.md's rule for this is that the
blocklist lives in code and not in a comment; the same should go for the
statement of what escapes it.

This does not route the raw paths through the guard -- the researcher's call,
2026-09-24: leave the control as it is, it should not block anything for now.
It captures what they actually put on the wire and checks the claim instead.
"""
from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PANEL_DIR = ROOT / "virtual_pxc"

if not (PANEL_DIR / "virtual_pxc.py").is_file():
    pytest.skip("virtual PXC not present in the repository",
                allow_module_level=True)
sys.path.insert(0, str(PANEL_DIR))

import virtual_pxc                                        # noqa: E402
import p2_scanner as ps                                   # noqa: E402


@pytest.fixture()
def panel():
    p = virtual_pxc.VirtualPxc.from_fixtures(PANEL_DIR / "fixtures.json")
    p.start()
    try:
        yield p
    finally:
        p.stop()


@pytest.fixture()
def emitted(monkeypatch):
    """Every frame the scanner puts on a socket, split into opcodes."""
    frames: list[bytes] = []
    real = socket.socket.sendall

    def spy(self, data, *a, **kw):
        frames.append(bytes(data))
        return real(self, data, *a, **kw)

    monkeypatch.setattr(socket.socket, "sendall", spy, raising=True)
    return frames


def _opcodes(frames: list[bytes]) -> list[int]:
    """Opcodes of every complete frame in the capture.

    A single sendall may carry a batch (discover_devices_on_node concatenates
    up to a batch's worth), so walk each buffer by its length prefixes.
    """
    out = []
    for buf in frames:
        off = 0
        while off + 12 <= len(buf):
            total = struct.unpack(">I", buf[off:off + 4])[0]
            if total < 12 or off + total > len(buf):
                break
            rh = ps._parse_routing_header(buf[off + 12:off + total])
            if rh is not None and len(rh[2]) >= 2:
                out.append(struct.unpack(">H", rh[2][:2])[0])
            off += total
    return out


def _drive(panel, monkeypatch):
    """Run the raw-frame paths. Outcomes do not matter here; the frames do."""
    monkeypatch.setattr(ps, "P2_PORT", panel.port)
    monkeypatch.setattr(ps, "P2_NETWORK", panel.bln)
    monkeypatch.setattr(ps, "P2_SITE", panel.site)

    ps.probe_p2_host(panel.host)
    ps.get_node_info(panel.host, panel.node)
    ps.enumerate_fln_devices(panel.host, panel.node)
    ps._cold_probe(panel.host, panel.bln, "P2SCAN", panel.node,
                   site=panel.site, timeout=2.0)
    ps._cold_status_query_probe(panel.host, panel.bln, timeout=2.0)
    ps.cold_discover_silent_sysinfo(panel.host, {
        "bln": panel.bln, "panel_name": panel.node,
        "supervisor_name": "P2SCAN", "site": panel.site,
    }, timeout=2.0)


def test_every_raw_path_emits_an_opcode_the_guard_would_permit(panel, emitted,
                                                               monkeypatch):
    _drive(panel, monkeypatch)
    ops = _opcodes(emitted)
    assert ops, "captured nothing; the drive did not reach the panel"

    for op in sorted(set(ops)):
        try:
            ps.check_emit_allowed(op)
        except PermissionError as exc:
            pytest.fail("raw path emits %s, which the guard forbids: %s"
                        % (ps.op_label(op), exc))


def test_the_only_ebln_opcodes_on_a_raw_path_are_the_two_documented(panel,
                                                                    emitted,
                                                                    monkeypatch):
    """The docstring's specific claim, not just the general one."""
    _drive(panel, monkeypatch)
    ebln = {op for op in _opcodes(emitted) if 0x4600 <= op <= 0x46FF}
    assert ebln <= {0x4634, 0x4640}, \
        "an EBLN opcode outside the audited pair reached a raw path: %s" % \
        sorted(hex(o) for o in ebln)


def test_the_guard_still_refuses_what_it_is_for():
    """So the tests above cannot pass because the guard permits everything."""
    for op in sorted(ps.EBLN_WRITES)[:1] + sorted(ps.EBLN_STALL_RISK)[:1]:
        with pytest.raises(PermissionError):
            ps.check_emit_allowed(op)
