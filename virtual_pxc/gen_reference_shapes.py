# -*- coding: utf-8 -*-
"""Distil real panel responses into a shippable, site-safe structure reference.

The verifier compares the virtual panel's responses against real captured ones.
Those captures cannot ship -- they carry point names, node names and readings.
What CAN ship is the STRUCTURE: for each opcode, the sequence of "a TLV here, a
run of raw bytes there", with the lengths stripped out.

    real body    T6 T0 <5B> T6 T0 <2B> T6 T0 T12 <14B> T5 <7B> T0 <1B> T1
    shipped      T  T  <>   T  T  <>   T  T  T   <>    T  <>   T  <>   T

Lengths are dropped deliberately, not for brevity. A TLV length is a name's
length, and a distribution of name lengths from one site is weak but non-zero
information about that site -- the same objection that withdrew the
`35 + node-name length` rule from the document. Structure carries none of it,
and structure is what the verifier actually asserts on.

Output: `reference_shapes.json`, a few KB, publishable.
"""
from __future__ import print_function
import collections
import json
import os
import pickle
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# mock/ -> bridge_work/ -> working/ -> project root
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
CACHE = os.path.join(ROOT, "working", "sweep", "bodies.pkl")
OUT = os.path.join(HERE, "reference_shapes.json")


def skeleton(body: bytes) -> str:
    out, p, raw = [], 0, 0
    while p < len(body):
        if p + 3 <= len(body) and body[p] == 0x01:
            L = struct.unpack(">H", body[p + 1:p + 3])[0]
            if 0 <= L < 256 and p + 3 + L <= len(body):
                if raw:
                    out.append("<>")
                    raw = 0
                out.append("T")
                p += 3 + L
                continue
        raw += 1
        p += 1
    if raw:
        out.append("<>")
    return " ".join(out)


def main() -> int:
    rsp = pickle.load(open(CACHE, "rb"))["rsp"]
    doc = {
        "_comment": (
            "Structure of real APOGEE PXC responses, by opcode, for verifying an "
            "implementation. 'T' is a TLV, '<>' a run of non-TLV bytes. Lengths "
            "and contents are deliberately absent: a TLV length is a name's "
            "length, and this is derived from one site's captures."),
        "_generated_by": "gen_reference_shapes.py",
        "opcodes": {},
    }
    for op in sorted(rsp):
        bodies = rsp[op]
        if not bodies:
            continue
        c = collections.Counter(skeleton(b) for b in bodies)
        doc["opcodes"]["0x%04X" % op] = {
            "bodies": len(bodies),
            "structures": [{"skeleton": s, "bodies": n} for s, n in c.most_common()],
        }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)

    n_op = len(doc["opcodes"])
    n_sk = sum(len(v["structures"]) for v in doc["opcodes"].values())
    print("opcodes: %d   distinct structures: %d   size: %d B"
          % (n_op, n_sk, os.path.getsize(OUT)))

    # Site-safety assertion, not a comment: nothing but T, <> and spaces.
    bad = [s["skeleton"] for v in doc["opcodes"].values()
           for s in v["structures"]
           if set(s["skeleton"].split()) - {"T", "<>"}]
    print("skeletons containing anything but T / <> : %d" % len(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
