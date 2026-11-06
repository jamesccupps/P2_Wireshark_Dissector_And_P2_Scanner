"""Generate p2_virtual_pxc_sample.pcap -- a P2 sample capture with no site data.

The P2 bytes are real: p2_scanner's own client code talking to the virtual
PXC's fixture panel over loopback, every write recorded as it was handed to
the socket. Only the wrapper is synthetic: Ethernet, IPv4 and TCP headers are
built here, because a loopback capture needs a capture driver and privileges
and would carry 127.0.0.1 instead of a documentation address.

Writes are recorded on BOTH sides rather than the client's reads, so segment
boundaries are the ones a panel and a client actually produce -- the client
reads a length prefix and then the remainder, and recording its reads would
split every panel frame into an artificial 4-byte segment.

Addresses are RFC 5737 TEST-NET-1 (192.0.2.0/24) with locally administered
MACs. Every name -- BLN MYBLN, panel NODE1, site BUILDING1, the devices and
points -- comes from virtual_pxc/fixtures.json, which is synthetic.

    python captures/make_sample_capture.py
"""
from __future__ import annotations

import contextlib
import io
import itertools
import socket
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "virtual_pxc"))

import p2_scanner as ps   # noqa: E402
import virtual_pxc        # noqa: E402

OUT = HERE / "p2_virtual_pxc_sample.pcap"
CLIENT_IP, PANEL_IP = "192.0.2.10", "192.0.2.20"
CLIENT_MAC, PANEL_MAC = bytes.fromhex("02000000000a"), bytes.fromhex("020000000014")
EPOCH = 1767225600            # 2026-01-01 00:00:00 UTC: a fixed, obviously synthetic start
MSS = 1460


# -- recording -----------------------------------------------------------------

class _FixedClock:
    """The time module, except that time() reads a fixed epoch. Everything else
    -- monotonic(), sleep() -- is the real one, so timeouts still work."""

    def __init__(self, real, epoch):
        self._real, self._epoch = real, epoch

    def time(self):
        return float(self._epoch)

    def __getattr__(self, name):
        return getattr(self._real, name)


events = []                   # (monotonic time, client ephemeral port, "c2s"|"s2c", bytes)


def _record(sock, data, panel_port):
    try:
        local, peer = sock.getsockname()[1], sock.getpeername()[1]
    except OSError:
        return
    if peer == panel_port:
        events.append((time.monotonic(), local, "c2s", bytes(data)))
    elif local == panel_port:
        events.append((time.monotonic(), peer, "s2c", bytes(data)))


def drive(panel):
    """One supervisor-style session plus the two raw-socket helpers."""
    real_sendall = socket.socket.sendall

    def spy(self, data, *a, **kw):
        _record(self, data, panel.port)
        return real_sendall(self, data, *a, **kw)

    socket.socket.sendall = spy
    counter = itertools.count(0x1000)
    ps.secrets.randbits = lambda k: next(counter) & ((1 << k) - 1)   # stable P2 sequences
    ps.P2_PORT, ps.P2_NETWORK, ps.P2_SITE = panel.port, panel.bln, panel.site
    # P2_PORT has to be the fixture's loopback port so the raw helpers can reach
    # it, but it also supplies the identity's |port suffix. The capture says 5033,
    # so the identity must too.
    ps.effective_scanner_name = lambda: "P2SCAN-LAP|5033"
    # The identity block carries a 4-byte wall-clock stamp; take it from the
    # capture's own synthetic clock so the bytes agree with the frame times and
    # the file is the same on every run.
    ps.time = _FixedClock(time, EPOCH)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            conn = ps.P2Connection(panel.host, port=panel.port, network=panel.bln)
            assert conn.connect(panel.node.lower()), "handshake failed"
            conn.read_system_info_compact(panel.node.lower())
            conn.read_point("VAV001", "ROOM TEMP", panel.node.lower())
            conn.read_point("VAV001", "NO SUCH POINT", panel.node.lower())    # -> an error response
            panel.push_dbchange(virtual_pxc.OP_DBCHANGE_POINT)                # unsolicited push
            time.sleep(0.05)
            conn.browse_device("VAV002", panel.node.lower())
            conn.enumerate_all_points(panel.node.lower(), max_points=20)
            conn.close()
            ps.enumerate_fln_devices(panel.host, panel.node)
            ps.get_node_info(panel.host, panel.node)
    finally:
        socket.socket.sendall = real_sendall
        ps.time = time


# -- framing ---------------------------------------------------------------------

def _csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _ip(addr):
    return socket.inet_aton(addr)


class Writer:
    def __init__(self):
        self.records, self.ip_id = [], 1

    def segment(self, ts, src, dst, sport, dport, seq, ack, flags, payload=b""):
        smac, dmac = (CLIENT_MAC, PANEL_MAC) if src == CLIENT_IP else (PANEL_MAC, CLIENT_MAC)
        tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
        pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack("!H", _csum(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), self.ip_id,
                         0x4000, 64, 6, 0, _ip(src), _ip(dst))
        ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
        self.ip_id += 1
        frame = dmac + smac + b"\x08\x00" + ip + tcp + payload
        self.records.append((ts, frame))

    def write(self, path):
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, frame in sorted(self.records, key=lambda r: r[0]):
                sec = int(ts)
                fh.write(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), len(frame), len(frame)))
                fh.write(frame)


SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


STEP = 0.002                  # synthetic spacing between successive writes, seconds


def build(events):
    # Loopback timing jitters from run to run, so real elapsed times would make
    # every regeneration a different file. The ORDER of writes is deterministic
    # -- the session is sequential -- so each write is placed by its rank.
    order = sorted(range(len(events)), key=lambda i: events[i][0])
    events = [(EPOCH + rank * STEP,) + events[i][1:] for rank, i in enumerate(order)]
    w = Writer()
    t0 = EPOCH
    conns = {}
    for n, key in enumerate(dict.fromkeys(e[1] for e in events)):
        conns[key] = {"cport": 50000 + n, "seq": {"c2s": 100000 * (n + 1), "s2c": 900000 * (n + 1)}}
    by_conn = {k: [e for e in events if e[1] == k] for k in conns}
    for key, evs in by_conn.items():
        c = conns[key]
        cp, seq = c["cport"], c["seq"]
        start = EPOCH + (evs[0][0] - t0) - 0.002
        w.segment(start, CLIENT_IP, PANEL_IP, cp, 5033, seq["c2s"], 0, SYN)
        w.segment(start + 0.0003, PANEL_IP, CLIENT_IP, 5033, cp, seq["s2c"], seq["c2s"] + 1, SYN | ACK)
        seq["c2s"] += 1; seq["s2c"] += 1
        w.segment(start + 0.0006, CLIENT_IP, PANEL_IP, cp, 5033, seq["c2s"], seq["s2c"], ACK)
        ts = start
        for t, _k, d, data in evs:
            ts = max(EPOCH + (t - t0), ts + 0.0001)
            src, dst, sp, dp, rev = ((CLIENT_IP, PANEL_IP, cp, 5033, "s2c") if d == "c2s"
                                     else (PANEL_IP, CLIENT_IP, 5033, cp, "c2s"))
            for i in range(0, len(data), MSS):
                chunk = data[i:i + MSS]
                w.segment(ts, src, dst, sp, dp, seq[d], seq[rev], PSH | ACK, chunk)
                seq[d] += len(chunk)
                ts += 0.00005
            w.segment(ts + 0.0002, dst, src, dp, sp, seq[rev], seq[d], ACK)   # the receiver's ACK
        end = ts + 0.001
        w.segment(end, CLIENT_IP, PANEL_IP, cp, 5033, seq["c2s"], seq["s2c"], FIN | ACK)
        w.segment(end + 0.0003, PANEL_IP, CLIENT_IP, 5033, cp, seq["s2c"], seq["c2s"] + 1, FIN | ACK)
        w.segment(end + 0.0006, CLIENT_IP, PANEL_IP, cp, 5033, seq["c2s"] + 1, seq["s2c"] + 1, ACK)
    return w


def main():
    panel = virtual_pxc.VirtualPxc.from_fixtures(ROOT / "virtual_pxc" / "fixtures.json",
                                                 cov_push_enabled=False)
    panel.start()
    try:
        drive(panel)
    finally:
        panel.stop()
    if not events:
        sys.exit("nothing was recorded; refusing to write an empty capture")
    w = build(events)
    w.write(OUT)
    n_conn = len(dict.fromkeys(e[1] for e in events))
    print("%s: %d frames, %d connections, %d P2 writes"
          % (OUT.name, len(w.records), n_conn, len(events)))


if __name__ == "__main__":
    main()
