# Siemens APOGEE P2 (Protocol II)

Tools and a technical reference for **P2 ("Protocol II")**, the Siemens APOGEE
building-automation protocol over TCP — for owner-operators working with their own legacy
equipment:

- **[`PROTOCOL.md`](PROTOCOL.md)** — a wire-level technical reference for the protocol.
- **`p2.lua`** — a Wireshark dissector that decodes P2 on the wire (passive).
- **`p2_gui.py` / `p2_scanner.py`** — a scanner that reads from panels (active; see the
  *P2 Scanner* and *Scope & ethics* sections below), with `firmware_registry.py` (shared
  panel build-tag cache) and `analyze_pcap.py` (offline opcode/error census over a capture).
- **[`virtual_pxc/`](virtual_pxc/)** — a virtual PXC panel to develop and test a P2 client
  against, which **enforces the rules a real panel enforces** rather than answering
  anything. No hardware needed.
- **[`bridge/`](bridge/)** — a read-only P2 → BACnet/IP bridge, exposing APOGEE points to
  any BACnet supervisor. A separate application with its own dependency; the scanner does
  not need it, and cloning this repository for the scanner alone installs nothing.

The dissector is built and validated from wire captures; the opcode names are the
protocol's AP2 function-code vocabulary.

> **v2.10.0 — a virtual panel you can develop against, and a BACnet bridge.**
> [`virtual_pxc/`](virtual_pxc/) is a virtual APOGEE panel that **refuses what a
> real panel refuses**: it validates `msg_type` as `13 + routing-slot bytes` and
> **drops a mismatch silently**, answers an unimplemented opcode with
> `not_found` rather than a synthetic success, and can be told to drop or refuse
> connections so a client's reconnect path actually runs. It ships the
> *structure* of real captured panel responses across **70 opcodes** — lengths
> and contents stripped, so it is publishable — and `verify.py` checks itself
> against `PROTOCOL.md` and that reference, reporting what it does **not** model
> rather than passing over it. [`bridge/`](bridge/) is a read-only P2 → BACnet/IP
> bridge; `bacpypes3` lives in `bridge/requirements.txt` and never at the
> repository root, so cloning this repo for the scanner alone still installs
> nothing. First CI too, now **126 tests** across three jobs on Python
> 3.10–3.13 — every public tool here is under test.
>
> **Also in 2.10.0 — `PROTOCOL.md` §14 was wrong about 9.3% of PPCL.** It said
> twenty-nine statements account for all 4,731 statement lines. They account for
> 4,291; the other **440 are assignments**, `<point> = <expression>`, whose
> leading token is a point name and not a keyword. A parser matching keywords
> against a line's first token works on ten lines in eleven and then fails on
> ordinary arithmetic. `OIP`'s `[OPEN]` closes, `LN` is gone, and §15.3.1's
> SSTO round-trip warning is re-pointed at the field that actually holds the
> panel's learned state. Full account in the [changelog](CHANGELOG.md).
>
> **v2.9.1 — `EQUAL` and `LESS` are reserved words after all.** v2.9.0
> removed them from `PROTOCOL.md` §14.3's PPCL reserved-word set, reasoning that
> they were a two-column vendor table's *description* column read as tokens.
> **That correction was wrong.** Both words appear in two independent vendor
> *enumerations* — the Insight Program Editor's reserved-word page and
> 125-1896 Rev. 5 chapter 5 — each in its own alphabetical cell, on pages with
> no description column at all. **If you built a PPCL tokenizer or linter from
> v2.9.0, its reserved-word list is two entries short.** What no edition had
> right: they are reserved *names*, not operators — no vendor source documents
> a syntax for either.
>
> §14's resident-point table is also corrected: `LOCAL` is a **declaration
> keyword**, `TOTAL` a **function**, `LOW` and `FAILED` **status values**. A
> client resolving those as resident points reads the statements wrong.
> Full account in the [changelog](CHANGELOG.md).
>
> Earlier releases are in the [changelog](CHANGELOG.md).

Click a P2 packet and get:

- **Frame header** — total length, header length (checked against the slots the
  frame actually carries, and flagged on a mismatch), sequence, direction
- **Routing slots** — the four NUL-terminated ASCII slots `[BLN, dst-node, BLN, src-node]`
- **Opcode** — the 2-byte AP2 function code, labelled against the full
  name set; an opcode that isn't a defined function code shows as `unknown_0x….`
- **Operand** (`p2.operand`) — many opcodes are one operation with a parameter
  encoded in the opcode rather than the body, so a run of consecutive codes is an
  enumeration: `0x0220`–`0x022C` is *point log* with thirteen filters,
  `0x0244`/`0x0245`/`0x024C`/`0x024D` is *point command* with four states,
  `UPL_DEL_x`/`UPL_ADDED_x`/`UPL_ALL_x` is one upload with three phases. Where
  the opcode is part of such a family the dissector names the operand —
  `point log - filter: value` — and appends it to the Info column. 55 families,
  146 opcodes; about a fifth of the request frames in a real capture carry one.
- **Per-opcode body** — wire-verified decoders for the common operations:
  - **COV value push** (`0x0274`) — point name, present value (`f32` BE), and the
    10-byte condition/priority block split into its named fields
    (priority, control status, out-of-service / failed / proof / disabled / commanded
    flags, alarm state, alarm priority)
  - **Node-name-table replication** (`0x4634`) — the roster digest: each node name
    plus its version (change generation)
  - **Identity / keepalive exchange** (`0x4640`, `EBLN_PING`) — node / site / BLN identity,
    on session-establish and on the ~10-second heartbeat
  - **Addressing-family requests** — point read/command (`0x0220`/`0x0240`/`0x0241`), COV
    enable/disable (`0x0271`/`0x0273`), trend and bulk upload: scope tag + command priority,
    name + suffix, and (for commands) the `f32` value
  - **Alarm reports** (`0x0508`) — point + descriptor, the value block, and the event
    timestamps
  - **Enhanced-alarm definitions** (`0x0983` responses) — point, mode point, units,
    set point, and the alarm-level table: offset, priority, category and message
    number per level
  - **Equipment scheduling** (`0x0987`/`0x0988`/`0x0989` responses) — the zone, the
    per-mode command table (which point is driven to what value in each mode), and
    the mode schedule with its effective-from/until dates and start time. Dates
    carry a weekday byte, and the dissector checks it against the date — a
    mismatch is reported rather than hidden
  - **Responses** — correlated to their request by sequence and decoded: the
    `CABINET_DISPLAY` firmware banner, value/read results, and the identity block
  - **Scope tag + command priority**, **error codes**, and a generic TLV / value walk
    for everything else
- **Expected-body schema** — for ~440 opcodes, a `[struct-derived]` note listing the
  fields the body is expected to contain (see *Schema notes* below)

## Install

1. **Help → About Wireshark → Folders → "Personal Lua Plugins"**
   - Windows: `%APPDATA%\Wireshark\plugins\`
   - Linux / macOS: `~/.local/lib/wireshark/plugins/`
2. Drop `p2.lua` into that folder
3. **Analyze → Reload Lua Plugins** (`Ctrl+Shift+L`) or restart Wireshark

The Protocol column shows `P2` on TCP/5033 and TCP/5034 traffic. You can also load it
ad hoc: `tshark -X lua_script:p2.lua -r capture.pcapng`.

**If it loads but nothing decodes**, check that the protocol is not disabled.
Wireshark remembers a disabled protocol across sessions, in
`%APPDATA%\Wireshark\disabled_protos` (`~/.config/wireshark/disabled_protos`),
and a disabled dissector still registers and is simply never called — so P2
traffic decodes as plain `tcp:data` with no error anywhere. Re-enable it under
**Analyze → Enabled Protocols**, remove the `p2` line from that file, or pass
`--enable-protocol p2` to tshark.

## Ports

- **TCP/5033** is the canonical, default P2 port — every field panel (and the
  supervisor) listens here for inbound P2.
- **TCP/5034** is, in some deployments, a second supervisor-side listener carrying the
  panel→supervisor push/announce (reverse) channel. It is optional and
  deployment-specific; the protocol on it is identical to 5033.
- **Two listeners on one host may not be the same service.** At one observed
  supervisor the canonical 5033 was already taken by another product, so the P2
  peer service was configured onto 5034. Panel-initiated sessions succeed on
  5034; on 5033 the connection is accepted, the request read, and the session
  closed with no reply — 984 times in 25 minutes, nine panels retrying every
  14 s. An open port is not a promise that the peer speaks P2.

The dissector binds both. For any other port, use **Analyze → Decode As…** to map it to
`P2`. Frame semantics derive from the frame's contents and direction, never from the TCP
port it arrived on.

## Coverage at a glance

- **Header length, not message class** — the `u32` at offset 4 is
  `13 + the total bytes of the four routing slots`, so its value is a sum of node-name
  lengths and differs from site to site. **Compute it; never choose it.** An earlier
  edition of this project read the six values it happens to take at one site as a set of
  message classes in legacy/modern pairs, and that model is withdrawn — see
  `PROTOCOL.md` §6.2, and §6.6 for the withdrawal. The traffic those values were
  attached to is real and is selected by **opcode**: the `EBLN_PING 0x4640` identity
  exchange, DB-change and replication records, and alarm prints.
- **Opcodes** — 638 AP2 function codes are named (the 630-value vendor enum plus
  eight panel-side codes), matching the `PROTOCOL.md` §9.5 catalog one-for-one —
  the catalog is generated from the same table the tools ship, so they cannot drift. The common operations are byte-decoded; the rest show their name +
  expected-body schema + a generic body walk. An opcode outside the catalog renders as
  `unknown_0x….`
- **Errors** — all seven wire-observed codes from `PROTOCOL.md` §7.2.2: `0x0003`
  not_found, `0x00AC` not_supported, `0x0E15` not_commandable, `0x0002` out_of_scope,
  `0x0E11` already_exists, plus `0x0E12` and `0x0009`, whose precise meanings are not yet
  established (Appendix D item 3).
- **Values** — big-endian `f32`; the COV condition/priority block decoded field by field.

## Correctness notes

- **The opcode is present only on request/push frames (direction `0x00`)**, and it sits
  at a *variable* offset (immediately after the four NUL-terminated routing slots). The
  dissector scans the four NULs rather than assuming a fixed offset — reading the
  post-slot bytes off a success/error response would fabricate phantom opcodes.
- **There is no multicast "presence beacon."** Earlier versions decoded UDP/10001 to
  `233.89.188.1` as a Siemens P2 beacon; that traffic is actually unrelated
  gateway/heartbeat multicast, not P2. The real, *optional* Ethernet-BLN availability
  multicast is `234.5.6.7:8` and is **disabled by default** — a peer-liveness heartbeat,
  not a discovery mechanism. The decoder has been removed to avoid false positives.
- Routing-slot ordering is destination-first within the request direction; the BLN-name
  slot is the membership/admission key.

## Schema notes

For opcodes whose request body is defined by the AP2 type system, the dissector shows
an **expected-body schema** — the field list the body *should* contain. This is a
struct-derived aid, **not** a guaranteed byte layout: P2's body encoding uses TLV
framing, scope tags, and field widths that are only fully pinned for the wire-verified
opcodes. As live captures confirm an opcode's exact layout, its schema note is upgraded
to a real, byte-level field decode (as already done for COV, the replication roster, and
the identity exchange). Treat un-upgraded schema fields as expectations, not decoded
bytes.

## Useful tshark one-liner

Heuristic to spot Siemens PXC field panels in a capture without decoding payloads — PXCs
(Nucleus NET RTOS) characteristically emit `TTL=64` with a small fixed TCP window:

```bash
tshark -r capture.pcapng -Y "tcp.flags.syn==1" \
    -T fields -e ip.src -e ip.ttl -e tcp.window_size_value | sort -u
```

What a supervisor is actually asking for, by operand:

```bash
tshark -r capture.pcapng -X lua_script:p2.lua -Y p2.operand \
    -T fields -e p2.opcode -e p2.operand | sort | uniq -c | sort -rn
```

## Protocol specification

[`PROTOCOL.md`](PROTOCOL.md) is the wire-level reference behind both tools: transport and
framing, the encoding primitives, addressing, the function-code (opcode) catalog and body
structures, the point model, change-of-value and alarming, PPCL over the wire, and security
considerations — with every claim evidence-tagged (`[W]` wire-observed / `[S]`
struct-derived / `[D]` vendor-doc / `[I]` inferred / `[OPEN]`). Start with its **Summary**
for the one-screen overview.

## Decoding a body into named fields

`PROTOCOL.md` documents the body structure of 457 operations. Two modules make that
machine-readable, so a tool does not have to guess at a body's shape:

- **`p2_asdu.py`** — the structure catalog, generated and embedded: field order and type
  for 1,019 structures (3,525 fields), every pinned type width, the parent-qualified
  types whose layout depends on what encloses them, and the recovered CHOICE tag maps.
  Data only; do not hand-edit it.
- **`p2_body.py`** — the walker that reads it. Hand-written, and kept separate so
  regenerating the catalog cannot overwrite it.

```python
from p2_body import decode

r = decode(0x0981, "rsp", body)          # "req" for a request or push
print(r.struct, r.consumed, "of", r.length, r.error)
for f in r.fields:
    print(f.path, f.type, f.offset, f.width, f.value)
```

`decode` never raises: an unexpected body returns the fields it managed to read plus an
`error` saying where it stopped, because a partial decode is more useful than an
exception and a malformed body is a normal thing to meet on a wire. Where a CHOICE's tag
map is not known, the arm is selected positionally and the field is **marked as such** —
`PROTOCOL.md` §10.4.1 shows that reading is wrong for four CHOICEs, so a caller has to be
able to tell a known selection from a guessed one.

`analyze_pcap.py --decode` runs it over every request body in a capture and reports how
far the declared structures got; `--decode-dump=N` prints the first N bodies field by
field. Over a 3,983-request reference capture: 3,835 bodies fully consumed, 144 with
trailing bytes the structure does not account for, 4 with no declared structure, and no
failures.

## P2 Scanner (companion active tool)

Alongside the passive dissector, this repository includes an **active** P2 scanner — a
client that connects to panels and reads from them, for an owner-operator inventorying and
monitoring **their own** equipment. It is the opposite end of the spectrum from the
dissector: the dissector only *watches* traffic, the scanner *sends* requests.

**Files (no data files needed):**

- `p2_gui.py` — a single-file Tkinter GUI. Edit your site settings in-app (no `site.json`
  required), discover/scan panels, browse the node/device tree, read and walk points, dump
  PPCL programs, compare scans, and export results to CSV/JSON. (The passive COV/push
  listener is CLI-only — see `--listen-push` below.)
- `p2_scanner.py` — the scanner library/CLI. Self-contained: the FLN/TEC point catalog is
  embedded, so it runs as one file. (An external `tecpoints.json` is still honored if you
  drop one in, to update the catalog.)
- `firmware_registry.py` — a small shared helper (per-panel build-tag cache; the
  build tag identifies the platform and its string encoding, and selects nothing
  about framing).

**Run it:**

```bash
python p2_gui.py            # GUI — recommended; edit config, scan, view, export
python p2_scanner.py --help # CLI
```

Common invocations:

```bash
# Inventory one panel's points
python p2_scanner.py --node 192.0.2.10 --network MYBLN --read-all

# Passive listen for COV / alarm pushes, pinned to the automation VLAN
python p2_scanner.py --listen-push 300 --listen-bind 192.0.2.50 --format json

# Offline opcode / error census over an existing capture
python analyze_pcap.py capture.pcapng
```

### CLI reference

Requires Python 3.10+ and the standard library only (the GUI additionally needs
`tkinter`, which ships with most CPython builds; on Debian/Ubuntu install
`python3-tk`). No third-party packages.

**Target & connection**

| Flag | Purpose |
|---|---|
| `--node` | PXC controller IP or node name |
| `--pxc` | For --cold-discover: known PXC IP (skips port scan) |
| `--network` | P2 network name (auto-learned if not set) |
| `--port` | P2 ALN port (default: 5033). Override only where the configured P2 port is not 5033 — e.g. a site where a Datamate Advanced co-install bumped the s… |
| `--scanner-name` | Scanner identity on P2 network (overrides config; default from config, else the built-in scanner identity) |
| `--config` | Load site config from JSON file |
| `--save` | Save learned config to JSON file |
| `--site-hint` | For --cold-discover: override BACnet-inferred prefix |

**Discovery**

| Flag | Purpose |
|---|---|
| `--discover` | Discover nodes and devices |
| `--scan-network` | Probe all known nodes |
| `--range` | IP range to scan. Formats: 192.0.2.0/24, 192.0.2.1-254, 192.0.2, or single IP. Can specify multiple times. |
| `--auto-discover` | Polished one-shot cold discovery: auto-detects local subnet (if --range omitted), port-scans TCP/5033, bootstraps BLN + supervisor + per-panel name… |
| `--cold-discover` | Discover BLN/scanner/node names on an unknown site. Uses BACnet recon + Cartesian dictionary attack. |
| `--cold-delay` | For --cold-discover: delay between probes (default 0.3) |
| `--skip-bacnet` | For --cold-discover: skip BACnet phase |
| `--skip-portscan` | Skip port scan during discovery (use known nodes) |
| `--bacnet-duration` | For --cold-discover: BACnet listen seconds (default 30) |
| `--bacnet-interface` | For --cold-discover: bind interface (default 0.0.0.0) |
| `--with-panel` | Also scan panel-level points during discovery |
| `--list-nodes` | List known PXC nodes |

**Reading points**

| Flag | Purpose |
|---|---|
| `--device` | TEC device name (e.g., DEVICE1) |
| `--point` | Specific point(s) to read. Accepts point names ("ROOM TEMP |
| `--read-all` | Read all points on every discovered device |
| `--walk-points` | Use opcode 0x0981 to enumerate every point on a panel (more complete than 0x0986 FLN enumerate). Requires -n NODE. |
| `--browse` | Browse devices on a node |
| `--quick` | Quick scan (key points only) |
| `--force-slot` | When reading by slot number, attempt the read even if the slot is undefined in the app\'s point table (for protocol troubleshooting). |
| `--force-full` | For --cold-discover: enable exhaustive tier 3 sweep |
| `--read-delay` | Inter-read delay during a device scan (default: 0.05). Raise on slow controllers or where you want to throttle probe rate. |
| `--verify` | Verify which devices are actually online after discovery |
| `--show-app` | Show point table for TEC application |

**Panel info & programs**

| Flag | Purpose |
|---|---|
| `--info` | Show node firmware/revision info during discovery |
| `--sysinfo-compact` | Use opcode 0x010C (newer firmware) for panel info. Complements --info which uses legacy 0x0100. Requires -n NODE. |
| `--dump-programs` | Use opcode 0x0985 to read PPCL program source from a panel. Requires -n NODE. |

**Passive capture**

| Flag | Purpose |
|---|---|
| `--listen-push` | Bind to the supervisor port (default 5033) and collect PXC push notifications (COV events, BLN virtual updates, routing tables). No SECONDS = run u… |
| `--listen-port` | Port for --listen-push (default: 5033 — Siemens-canonical supervisor port per 149-1006; override if your site uses a different port, e.g. 5034 for… |
| `--listen-bind` | Local interface address for --listen-push (default: 0.0.0.0, all interfaces). Set this to the automation-VLAN address on a dual-homed host so the l… |
| `--listen-output` | Write captured events to FILE (default: stdout) |
| `--listen-no-ack` | Don't ACK incoming pushes (safer if a real DCC is also on the network) |
| `--sniff` | Live capture P2 traffic to learn network name (requires tshark/Wireshark, default 10s) |
| `--pcap` | Decode a pcap/pcapng file |

**Output & misc**

| Flag | Purpose |
|---|---|
| `--format` | Output format (default: table) |
| `--offline` | Only show devices confirmed offline (implies --verify) |
| `--online` | Only show devices confirmed online (implies --verify) |
| `--debug-reads` | Print raw hex when a point-read fails to parse (helpful for diagnosing unusual response shapes) |


The GUI imports the scanner at runtime, so keep the three `.py` files together. Site
configuration is edited in **File → Edit Site Config** and is applied immediately;
`site.json` is written only if you choose **Save Config**, and is otherwise optional.

## Virtual PXC (develop without a panel)

[`virtual_pxc/`](virtual_pxc/) is a virtual APOGEE PXC that runs in-process. Point a
scanner, a bridge, a dissector or your own client at it and it answers like a panel.

```python
from virtual_pxc import VirtualPxc

panel = VirtualPxc.from_fixtures("fixtures.json")
panel.start()                     # binds 127.0.0.1 on a free port
print(panel.host, panel.port)
...
panel.stop()
```

**What makes it worth pointing a client at is that it refuses what a real panel
refuses.** A fixture that answers everything proves nothing:

- **It enforces the header length.** `msg_type` is `13 + the total bytes of the four
  routing slots` ([§6.2](PROTOCOL.md)). A frame whose value disagrees with its own slots
  is **dropped silently** — no error, no reset, just nothing. That failure mode is hard
  to find in a building and trivial to find here. `0x33` and `0x34` get no special
  treatment; they are two lengths, not two dialects.
- **An unimplemented opcode gets `not_found`**, not a synthetic success — otherwise every
  operation you have not written yet looks like it works.
- **It talks first.** `push_dbchange()` sends an unsolicited `AP2_DBCHANGE_*`
  notification on the already-open session — a peer announcing a database change —
  in the shape measured on the wire: direction byte, four routing slots, opcode,
  no body. A client waiting on a reply has to recognise it and carry on.
- **It can fail on purpose.** `drop_connections()` cuts every live socket;
  `refuse_connections(n)` accepts and immediately closes the next *n*, which is what a
  panel that is up but not ready does. A client's reconnect and backoff paths are usually
  the least-tested code it has.

**Verify it against the document and against real panels:**

```bash
cd virtual_pxc
python -m pytest tests/ -q     # 12 framing tests
python verify.py               # frame invariants, response structure, capability table
```

`verify.py` holds the panel's own outbound frames to the same rules as its responses, and compares each response against `reference_shapes.json` — the *structure* of
real captured panel responses across **70 opcodes and 148 distinct structures**, with
lengths and contents stripped so it is publishable. It also reports what the virtual
panel does **not** model (unsolicited keepalives, EBLN replication, COV subscription
lifecycle, segmentation) rather than passing over it, because a fixture's gaps are where
a client's bugs hide.

No dependencies beyond the standard library and `pytest`.

## P2 → BACnet bridge

[`bridge/`](bridge/) exposes APOGEE points to any BACnet supervisor — Desigo CC, Niagara,
EBI, anything that speaks BACnet/IP. Every P2 point becomes a BACnet object; analog reads
become `analogInput`/`analogValue`, digital become `binaryInput`/`binaryValue`, and the
panel's `#COM` indicator propagates to `reliability` and the fault status flag so a
supervisor lights up red the same way Desigo does.

**Read-only by design**, the same posture as the scanner. The BACnet side advertises
exactly the six services it answers — `readProperty`, `readPropertyMultiple`, `i-Am`,
`i-Have`, `who-Is`, `who-Has`. `writeProperty` is not among them.

```bash
cd bridge
pip install -r requirements.txt          # bacpypes3, and nothing else
python p2_bridge_launcher.py             # GUI: configure, build a manifest, run
python p2_bacnet_bridge.py --help        # CLI
```

**It is a separate application.** `bacpypes3` is declared in `bridge/requirements.txt`
and never at the repository root, and the scanner does not import the bridge — so cloning
this repository to use the scanner or the dissector alone installs nothing. The bridge
imports `p2_scanner` from the root as a library; that is the whole dependency, and
`bridge/tests/test_symbol_resolution.py` fails the build if any of it moves.

## Scope & ethics

P2 has **no authentication and no encryption** — the only admission check is a matching
BLN name, which is visible in cleartext on every frame (it is an access label, not a
secret). That makes this tooling powerful and easy to misuse, so:

- **Use it only on networks and equipment you own or are explicitly authorized to test.**
  These tools are for owner-operators securing and maintaining their own legacy plant.
- **Read-only by default.** The scanner is built around reads, browse, and enumeration.
  It does **not** implement panel-destructive operations (cold/warm start, flash erase,
  node eviction) — and a conformant tool should refuse to, even behind a flag.
- **Active discovery leaves a footprint.** A correct-BLN handshake registers the scanner's
  identity as a permanent node-table entry on the panel (this is how P2 registration
  works). Prefer the passive push-listener and the dissector when you only need to observe.
- **Rate-limit and avoid production disruption.** Use inter-request delays, a single
  connection per panel, and do not run scans against life-safety or revenue-critical
  systems outside a maintenance window. The replication-class opcodes can stall a panel.
- **Never expose P2 to an untrusted network.** Segment it onto a dedicated, firewalled
  automation VLAN.

This split — a passive dissector plus a read-oriented scanner, with destructive operations
documented but not shipped runnable — is deliberate: it helps a defender understand and
secure their own system without handing an attacker a turnkey weapon.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests welcome — especially captures that
let an expected-body schema be promoted to a verified byte decoder (a point in alarm or
held under command, a node-name-table change, a large upload), new bespoke body
decoders, and edge-case fixes.

## License

MIT. See `LICENSE`.

This dissector is a third-party analytical tool built from observed traffic for owner-
operators of their own equipment. It is not affiliated with or endorsed by Siemens.
