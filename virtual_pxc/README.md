# Virtual PXC

An in-process virtual Siemens APOGEE PXC panel, speaking P2 over TCP. Point a
scanner, a bridge, a dissector or your own client at it and it answers like a
panel — including refusing what a panel refuses.

```python
from virtual_pxc import VirtualPxc

panel = VirtualPxc.from_fixtures("fixtures.json")
panel.start()                     # binds 127.0.0.1 on a free port
print(panel.host, panel.port)
...
panel.stop()
```

It exists because a test fixture that answers everything proves nothing. The
version this grew from accepted any `msg_type`, echoed it back, and replied to
unknown opcodes with a synthetic success — so a client carrying a wrong framing
model passed against it and failed in a building.

---

## What makes it worth pointing a client at

**It enforces the header length.** `msg_type` is `13 + the total bytes of the
four routing slots` ([`PROTOCOL.md`](../PROTOCOL.md) §6.2). A frame whose value
disagrees with its own slots is **dropped silently**, which is what a panel does
— no error, no reset, just nothing. That failure mode is hard to find in the
field and trivial to find here.

There is no "dialect". `0x33` and `0x34` are two lengths, not two protocols, and
this panel drops both unless the arithmetic happens to produce them.

**It answers `not_found`, not "sure, fine".** An opcode it does not implement
gets error `0x0003`. A fixture that fakes success makes every unimplemented
operation look implemented, and a client asserting "did it work" passes against
nothing.

**Its responses have the structure real panels emit.** `verify.py` compares each
response against `reference_shapes.json`, which records the *structure* of real
captured panel responses — 70 opcodes, 148 distinct structures. That caught a
hand-written `0x0981` body that parsed fine and looked nothing like a panel.

**It can fail on purpose.** `drop_connections()` cuts every live socket;
`refuse_connections(n)` accepts and immediately closes the next *n*. A client's
reconnect and backoff paths are usually the least-tested code it has.

---

## Verifying it

```
python verify.py
```

Three groups, and it reports what it does *not* do rather than passing over it:

| | |
|---|---|
| **Frame invariants** | `total_len` self-inclusive, `msg_type` computed, direction byte, role-swapped slots, sequence echo, wrong length dropped, undersized frame survived |
| **Response structure** | each opcode against the real-panel structures in `reference_shapes.json` |
| **Capability table** | the virtual-PXC rows of the project's Level 2 standard, marked PASS / PARTIAL / ABSENT |

Current: **19 PASS, 1 PARTIAL, 3 ABSENT, 0 FAIL.**

### `reference_shapes.json`

Real captures cannot ship — they carry point names, node names and readings.
This file carries the structure and nothing else:

```
real body   T6 T0 <5B> T6 T0 <2B> T6 T0 T12 <14B> T5 <7B> T0 <1B> T1
shipped     T  T  <>   T  T  <>   T  T  T   <>    T  <>   T  <>   T
```

Lengths are dropped deliberately. A TLV length is a name's length, and a
distribution of name lengths from one site is weak but non-zero information
about that site. Structure carries none of it, and structure is what the
comparison asserts on. Regenerate with `gen_reference_shapes.py` if you have a
body cache; the shipped file needs no input.

---

## What it does **not** model

Stated plainly, because a fixture's gaps are where a client's bugs hide.

| | |
|---|---|
| **EPing cadence / liveness** | answers `0x0100` when asked, but emits no unsolicited keepalive. A client that depends on being pinged will not notice here |
| **Node-name table / EBLN replication** | nothing. No versioning, no convergence, no peer discovery |
| **COV subscriptions** | pushes `0x0274` after a write, but keeps no subscribe/unsubscribe state — you cannot test subscription lifecycle |
| **Segmentation above 1,514 B** | not implemented, and `[OPEN]` in `PROTOCOL.md` too: never observed on the wire, so there is nothing to model against |
| **Session budgets, maintenance windows** | accepts as many connections as you open |
| **Persistence** | state is per-process |

It **does** handle pipelining: several requests arriving in one TCP segment are
all answered, in order (measured, not assumed — `verify.py` sends three).

---

## Fixtures

`fixtures.json` — three FLN devices across three TEC applications, seven
panel-internal points, and a handful of SYST objects. All identifiers are
generic placeholders (`BUILDING1`, `NODE1`, `VAV001`, `OA.TEMP`); no real-site
name, address or point appears in this directory.

Panel-internal points matter more than they look: they are reachable only
through the bulk enumerate `0x0981`, never through `0x0986`, so a fixture
without them leaves that whole path of a client untested. One is deliberately
label-only (no value) and one deliberately has no engineering units — both are
real cases that break naive parsers.

---

## Tests

```
python -m pytest tests/ -q
```

`tests/test_framing.py` pins the properties above: a correct header length is
answered, a wrong one is dropped silently (including `0x33` and `0x34`), slot 0
survives the round trip, the response's header length matches its *own* slots,
and an unknown opcode gets `not_found`. `strict_framing=False` reproduces the
permissive older behaviour so the difference stays visible.
