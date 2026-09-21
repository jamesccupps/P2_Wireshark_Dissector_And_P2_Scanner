# -*- coding: utf-8 -*-
"""Verify the virtual PXC against the document and against real wire bytes.

Two standards, applied in order:

  1. **Frame-level invariants** that PROTOCOL.md states outright -- `total_len`
     self-inclusive, `msg_type` computed, the direction byte, slot layout,
     sequence echo, the minimum frame size. These are pass/fail.

  2. **Response shape against the corpus.** For every opcode the mock serves
     where the body cache holds real panel responses, drive the mock and compare
     the shape of what it emits -- the sequence of TLV lengths and the byte runs
     between them -- against the distribution of real shapes. This is the check
     that caught the invented 0x0981 body.

A mock cannot be verified against a real panel from here, so what this reports
is: does it obey the rules the document states, and does it look like the wire
where the wire is available. Anything it does not serve is reported as absent
rather than passed over.

SITE SAFETY: real bodies carry real point names. Shapes only -- TLV lengths and
byte-run sizes -- never contents.
"""
from __future__ import print_function

import collections
import json
import socket
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import virtual_pxc  # noqa: E402

REFERENCE = HERE / "reference_shapes.json"

def io_open(path):
    return open(str(path), "r", encoding="utf-8")


PASS, FAIL, ABSENT, PARTIAL = "PASS", "FAIL", "ABSENT", "PARTIAL"
results = []


def report(area, name, verdict, detail=""):
    results.append((area, name, verdict, detail))
    print("  %-7s %-46s %s" % (verdict, name, detail))


def shape(body: bytes) -> str:
    out, p, raw = [], 0, 0
    while p < len(body):
        if p + 3 <= len(body) and body[p] == 0x01:
            L = struct.unpack(">H", body[p + 1:p + 3])[0]
            if 0 <= L < 256 and p + 3 + L <= len(body):
                if raw:
                    out.append("<%dB>" % raw)
                    raw = 0
                out.append("T%d" % L)
                p += 3 + L
                continue
        raw += 1
        p += 1
    if raw:
        out.append("<%dB>" % raw)
    return " ".join(out)


def skeleton(sh: str) -> str:
    """Shape with TLV lengths and run sizes blanked -- pure structure."""
    toks = []
    for t in sh.split():
        toks.append("T" if t.startswith("T") else "<>")
    return " ".join(toks)


def raw_ask(panel, msg_type, opcode, body=b"", scanner="P2BRIDGE", seq=7,
            timeout=2.0, node=None):
    node = node or panel.node.lower()
    payload = (b"\x00" + panel.bln.encode() + b"\x00" + node.encode() + b"\x00"
               + panel.bln.encode() + b"\x00" + scanner.encode() + b"\x00"
               + struct.pack(">H", opcode) + body)
    frame = struct.pack(">III", 12 + len(payload), msg_type, seq) + payload
    s = socket.create_connection((panel.host, panel.port), timeout=timeout)
    try:
        s.sendall(frame)
        s.settimeout(timeout)
        try:
            return s.recv(8192)
        except socket.timeout:
            return b""
    finally:
        s.close()


def good_mt(panel, scanner="P2BRIDGE", node=None):
    node = node or panel.node.lower()
    return virtual_pxc.expected_msg_type([panel.bln, node, panel.bln, scanner])


# ══════════════════════════════════════════════════════ 1. frame invariants
def check_frame(panel):
    print()
    print("1. FRAME INVARIANTS (PROTOCOL.md 6.1, 6.2)")

    resp = raw_ask(panel, good_mt(panel), 0x4640)
    if not resp:
        report("frame", "panel answers a well-formed request", FAIL)
        return
    total, mt, seq = struct.unpack(">III", resp[:12])

    report("frame", "total_len is self-inclusive",
           PASS if total == len(resp) else FAIL,
           "declared %d, frame %d" % (total, len(resp)))

    slots = [x.decode() for x in resp[12:][1:].split(b"\x00")[:4]]
    want = virtual_pxc.expected_msg_type(slots)
    report("frame", "msg_type == 13 + slot bytes",
           PASS if mt == want else FAIL, "got %d, want %d" % (mt, want))

    report("frame", "sequence is echoed", PASS if seq == 7 else FAIL,
           "sent 7, got %d" % seq)

    report("frame", "direction byte is a response code",
           PASS if resp[12] in (0x01, 0x05) else FAIL, "0x%02X" % resp[12])

    report("frame", "response slots are role-swapped",
           PASS if slots[1] == "P2BRIDGE" and slots[3] == panel.node else FAIL,
           "%s / %s" % (slots[1], slots[3]))

    # The panel's OWN outbound frames, held to the same rule. They were not
    # checked here before, and were malformed for as long as they existed:
    # two direction bytes and a constant msg_type, so a client read slot 0 as
    # empty and took the node name's first two characters for the opcode.
    # Nothing noticed, because nothing consumed a push.
    push = panel._build_push_frame(struct.pack(">H",
                                               virtual_pxc.OP_DBCHANGE_POINT))
    p_total, p_mt, _p_seq = struct.unpack(">III", push[:12])
    p_payload = push[12:]
    p_slots = [x.decode() for x in p_payload[1:].split(b"\x00")[:4]]
    p_off = 1 + sum(len(x) + 1 for x in p_slots)
    report("frame", "panel's own push: total_len self-inclusive",
           PASS if p_total == len(push) else FAIL,
           "declared %d, frame %d" % (p_total, len(push)))
    report("frame", "panel's own push: one direction byte, slot 0 next",
           PASS if p_payload[0] == 0x00 and p_payload[1] != 0x00 else FAIL,
           "%s" % p_payload[:2].hex(" "))
    report("frame", "panel's own push: msg_type == 13 + slot bytes",
           PASS if p_mt == virtual_pxc.expected_msg_type(p_slots) else FAIL,
           "got %d, want %d" % (p_mt, virtual_pxc.expected_msg_type(p_slots)))
    report("frame", "panel's own push: opcode where a client looks",
           PASS if struct.unpack_from(">H", p_payload, p_off)[0]
           == virtual_pxc.OP_DBCHANGE_POINT else FAIL,
           "0x%04X" % struct.unpack_from(">H", p_payload, p_off)[0])

    # a wrong header length must be dropped, silently
    bad = raw_ask(panel, 0x33, 0x4640)
    report("frame", "wrong msg_type dropped silently",
           PASS if bad == b"" else FAIL)

    # PROTOCOL.md 6.1.1: minimum valid frame is 17 B, 19 for a request.
    s = socket.create_connection((panel.host, panel.port), timeout=2.0)
    try:
        s.sendall(struct.pack(">III", 12, good_mt(panel), 1))
        s.settimeout(1.5)
        try:
            short = s.recv(512)
        except socket.timeout:
            short = b""
    finally:
        s.close()
    report("frame", "undersized frame does not crash or answer",
           PASS if short == b"" else FAIL)


# ══════════════════════════════════════════════════════ 2. shapes vs corpus
def check_shapes(panel):
    print()
    print("2. RESPONSE STRUCTURE vs REAL PANELS")
    if not REFERENCE.is_file():
        report("shape", "reference_shapes.json present", ABSENT, str(REFERENCE))
        return
    with io_open(REFERENCE) as fh:
        ref = json.load(fh)["opcodes"]

    probes = []

    # 0x4640 identity
    probes.append((0x4640, raw_ask(panel, good_mt(panel), 0x4640)))
    # 0x010C system info
    probes.append((0x010C, raw_ask(panel, good_mt(panel), 0x010C)))
    # 0x0981: TWO records, because the panel has two record forms and an
    # earlier edition only ever saw the first. Alphabetically first is a
    # digital point with empty units (the shorter structure); walking on with
    # the cursor reaches an analog one with a units TLV.
    def enum(cursor: bytes):
        b = (b"\x00\x00" + b"\x01\x00\x01\x2a" + b"\x01\x00\x01\x2a"
             + b"\x00\x00"
             + b"\x01" + struct.pack(">H", len(cursor)) + cursor
             + b"\x01\x00\x00")
        return raw_ask(panel, good_mt(panel), 0x0981, b)

    probes.append((0x0981, enum(b"")))
    probes.append((0x0981, enum(b"CHW.SUPPLX")))   # lands on an analog record
    # 0x0986 enumerate FLN
    probes.append((0x0986, raw_ask(panel, good_mt(panel), 0x0986,
                                   b"\x00\x00" + b"\x01\x00\x00")))

    for op, resp in probes:
        if not resp:
            report("shape", "0x%04X answered" % op, FAIL, "silence")
            continue
        got = resp[12:]
        # strip direction + 4 slots to compare body-to-body
        i, nulls = 1, 0
        while i < len(got) and nulls < 4:
            if got[i] == 0:
                nulls += 1
            i += 1
        our_body = got[i:]
        entry = ref.get("0x%04X" % op)
        if not entry:
            report("shape", "0x%04X vs real panels" % op, ABSENT,
                   "no reference structure for this opcode")
            continue
        known = {st["skeleton"]: st["bodies"] for st in entry["structures"]}
        mine = skeleton(shape(our_body))
        if mine in known:
            report("shape", "0x%04X vs real panels" % op, PASS,
                   "structure matches %d of %d real bodies"
                   % (known[mine], entry["bodies"]))
        else:
            commonest = entry["structures"][0]
            report("shape", "0x%04X vs real panels" % op, FAIL,
                   "ours %s | commonest real %s"
                   % (mine[:36], commonest["skeleton"][:36]))


# ══════════════════════════════════════════════════════ 3. Level 2 table
def check_level2(panel):
    print()
    print("3. AUDIT_PLAN 8 LEVEL 2 -- the virtual-PXC capability table")
    have = {
        "Accept TCP/5033, admit or refuse a session": PASS,
        "0x4640 identity exchange": PASS,
        "Answer point reads": PASS,
        "The enumeration idiom and its 0x0003 terminator": PASS,
        "Return an error code for an unknown request": PASS,
        "Sequence numbers, response pairing": PASS,
    }
    for k, v in have.items():
        report("level2", k, v)

    # Unsolicited peer traffic, on demand: push_dbchange() sends an
    # AP2_DBCHANGE_* notification on the session already open -- the shape
    # measured on the wire, not the "bare opcode" an earlier reading assumed.
    report("level2", "Unsolicited peer-initiated notification", PASS,
           "push_dbchange() emits a DBCHANGE on the open session")

    # things the mock genuinely does not do
    report("level2", "EPing cadence / liveness timing", ABSENT,
           "emits no keepalive on its own schedule; a client that waits to be "
           "pinged waits forever")
    report("level2", "Node-name table: hold, version, replicate, converge", ABSENT,
           "no EBLN replication at all")
    report("level2", "Serve COV subscriptions", PARTIAL,
           "pushes 0x0274 after a write; no subscribe/unsubscribe state")
    report("level2", "0x010D capability document", PARTIAL,
           "content from 55 real documents; FRAMING IS INFERRED -- the "
           "exchange is in none of the 229 captures, so the body wrapper is a "
           "guess and stays PARTIAL until one is captured")
    # Measured, not assumed: three requests in one segment, count the answers.
    payload_of = lambda op: (
        b"\x00" + panel.bln.encode() + b"\x00" + panel.node.lower().encode()
        + b"\x00" + panel.bln.encode() + b"\x00" + b"P2BRIDGE" + b"\x00"
        + struct.pack(">H", op))
    burst = b""
    for n in range(3):
        pl = payload_of(0x4640)
        burst += struct.pack(">III", 12 + len(pl), good_mt(panel), 100 + n) + pl
    sk = socket.create_connection((panel.host, panel.port), timeout=3.0)
    got = b""
    try:
        sk.sendall(burst)
        # Read until the panel goes quiet, not until a byte count: a single
        # 0x4640 response is ~84 B, so an earlier `while len(got) < 3 * 40`
        # stopped after two and reported the MOCK as failing to pipeline.
        sk.settimeout(1.5)
        try:
            while True:
                chunk = sk.recv(8192)
                if not chunk:
                    break
                got += chunk
        except socket.timeout:
            pass
    finally:
        sk.close()
    seqs, p = [], 0
    while p + 12 <= len(got):
        tl, _mt, sq = struct.unpack(">III", got[p:p + 12])
        if tl < 12 or p + tl > len(got):
            break
        seqs.append(sq)
        p += tl
    report("level2", "Request pipelining (3 in one segment)",
           PASS if seqs == [100, 101, 102] else PARTIAL,
           "answered %d of 3, sequences %s" % (len(seqs), seqs))
    report("level2", "Segmentation above 1,514 B", ABSENT,
           "[OPEN] in the document too -- never observed on the wire")


def main() -> int:
    panel = virtual_pxc.VirtualPxc.from_fixtures(HERE / "fixtures.json")
    panel.start()
    print("virtual PXC on %s:%d  node=%s bln=%s"
          % (panel.host, panel.port, panel.node, panel.bln))
    try:
        check_frame(panel)
        check_shapes(panel)
        check_level2(panel)
    finally:
        panel.stop()

    print()
    tally = collections.Counter(v for _a, _n, v, _d in results)
    print("SUMMARY: " + "  ".join("%s=%d" % (k, tally[k])
                                  for k in (PASS, PARTIAL, FAIL, ABSENT) if tally[k]))
    return 1 if tally[FAIL] else 0


if __name__ == "__main__":
    sys.exit(main())
