# Changelog

## Unreleased

### A CHOICE read as a fixed width, and a declared field that went missing

`p2_asdu` carries a `WIDTHS` entry for two types that are also CHOICEs, and
`p2_body`'s walker consulted `WIDTHS` **before** dispatching — so both were read
as opaque fixed-width blobs.

For `cov_limit_` that is harmless; both arms are four bytes after the tag. For
`which_trend_` the width of 4 is right only when the nested `Trend_type` selects
`point_cov`, whose arm is `NULL_`. Select `trend_cov` or `time` and a **declared**
four-byte `FLOAT_` falls outside the walk.

That is how `PROTOCOL.md` §10.2.3 came to record an **undeclared trailing resume
key** on the trend-delete request. There is no such key. `0x0291`'s trailing
bytes are `Trend_type`'s arm payload, and all fourteen corpus bodies now account
for themselves exactly:

| `trend_type` | arm | payload | bodies |
|---|---|---|---:|
| 0 | `point_cov` | none — the arm is `NULL_` | 6 |
| 1 | `trend_cov` | `cov_limit` = **3.0** | 2 |
| 2 | `time` | `seconds_interval` = **60.0** | 4 |

Corpus-wide: exact decodes **3,933 → 3,939**, errors **26 → 20**, nothing else
moved.

The fix suppresses the width lookup for a CHOICE rather than dispatching at that
point — `All_points` and `Alarm_object` also begin with a `tag_` and have their
own handlers further down, and dispatching every tag-led structure there
intercepts them and turns 26 decode errors into 446. Measured, not guessed. Six
tests, including that one.


### One panel point in four was published as the wrong kind of object

`0x0981` records were read by a three-shape heuristic. `AP2_Upl_All_Point_Response`
is a **declared structure**, and walking it wins on every axis measured over sixty
real bodies:

| | heuristic | structure walk |
|---|---|---|
| bodies read | 60 | **60, all clean** |
| point type | **not visible at all** | `LAO` 30, `LAI` 14, **`LDO` 12, `LDI` 4** |
| values recovered | 59 | **60** |
| units correct | 58 | **60** |

**Sixteen of sixty panel-resident points are digital**, and the bridge's manifest
builder hard-coded `analog_ro` for every one — so a digital point was published as
an `analogInput` reading 0.0 and 1.0 where a supervisor expects inactive and
active. It now takes the type from the record.

The two units the heuristic got wrong are both cases of reading a neighbouring
TLV; `eng_units` lives under the **analog arm** of the point structure (§11.5.1),
so a digital point has no units field rather than an empty one. That also settles
the last of the odd strings from the previous release: they are what the panel
holds.

The heuristic remains the fallback — `p2_body` is an optional import, and the
scanner must still run as a single file beside `p2_data.py`. A **truncated** walk
is refused on purpose: all sixty real bodies walk complete, so nothing in the
corpus says what a half-walked record should yield.

### Five point types do not fit a binary object, and now say so

`LOOAP` and `LOOAL` are OFF/ON/**AUTO**, `LFSSL` and `LFSSP` are STOP/SLOW/FAST,
`LENUM` has six states. A BACnet binary object holds two, and the vendor's own
model has `multiStateInput`/`Output`/`Value` for exactly this (`BAC_Point_Base`
arms 13, 14, 19).

**None of the five occurs anywhere in the corpus** — 1,070 catalogued
applications, 181,170 points, sixty panel records — so nothing maps them and
building the mapping now would be speculation. Instead the enumerate record
carries `n_states`, and the manifest builder **logs a warning** when it publishes
a point with more than two states as a binary object. If that ever fires at a
site, it is the evidence the mapping has been waiting for.


### `analyze_pcap.py`: a four-tuple is not a connection

The inventory tool keyed its reassembly buffers on
`(src_ip, src_port, dst_ip, dst_port)`. A peer that closes and reconnects from
the same ephemeral port — what tshark labels **[TCP Port numbers reused]** —
restarts near zero under relative sequence numbers, while the reader is holding
a write cursor far past it. **Every byte of the second connection read as a
retransmission and was discarded**, counted into the duplicate tally and never
mentioned.

Not hypothetical. Across the 40 P2-bearing captures in the corpus, three carry
port reuse, and on one of them it is **806 of 3,211 four-tuples**:

| | four-tuple key | with `tcp.stream` |
|---|---:|---:|
| frames | 124,123 | **125,237** |
| request opcodes | 63,649 | **64,763** |
| bytes called retransmissions | 99,625 | 1,593 |

**1,114 frames, 0.9%, silently gone.** `p2raw` solves the same problem by
splitting generations on a sequence jump; a streaming reader cannot look ahead,
but tshark already knows the answer and will say so for the cost of one more
field. `tcp.stream` now joins the key.

Cross-checked afterwards on the reference capture: **23,531 frames**, which is
exactly `p2raw`'s count, and `0x0951` × 11 / `0x0954` × 2 / `0x0955` × 3 /
`0x0956` × 2 / `0x0959` × 2, exactly the census figures. Three independent
readers, one number.

### `analyze_pcap.py`: a third hole that reported nothing

On an impossible length prefix the reader dropped its whole buffer and returned
**without counting anything**. The tool reports the bytes it trims as duplicates
and the bytes missing from the capture; a third discard that said nothing is the
one a reader cannot account for. It is now counted and printed.

The guard that decides "impossible" also moved: it admitted `total_len` 12,
which was then handed on as a frame with an empty payload and counted a header
length for something that cannot exist. **13 header bytes plus four NUL slot
terminators is 17** (§6.1.1), and a request adds two more for 19.

Neither fires on the corpus — the reference capture still reports 23,531
frames, and the port-reuse capture 125,237 — which is the point. A counter that
reads zero is evidence; a discard that prints nothing is not.

### `analyze_pcap.py` was the last public tool with no tests

**18 tests**, and the repository's `scanner` CI job already runs them: routing
offsets, the tallying of requests, errors, success responses and zero-length
bodies, and the reassembly cases that are the whole point — a frame split
across segments, several frames in one segment, a retransmission counted once,
a partial overlap keeping only its new tail, a gap that does not misalign what
follows, and the port reuse above.

Its output is entirely counts, so a defect in it does not crash. It prints a
smaller number.

## v2.10.1 — the frame that did not exist (2026-09-18)

A defect in `p2_scanner.py`, two in `virtual_pxc/`, the repository's first tests
for the scanner, and one settled question.

### `p2_scanner.py`: a predicate that could never be true

The scanner carried a set of five opcodes under this comment:

> Bare-opcode session keepalives. Panels emit these as 2-byte payloads with no
> direction byte and no body — the opcode IS the payload.

**No such frame exists.** Measured against a supervisor-side capture holding
twenty of them, and confirmed independently with `tshark`'s built-in TCP
dissector, every one is an **ordinary request**: direction byte, four routing
slots, the two opcode bytes, and a **zero-length body**. 48 bytes on the wire,
`msg_type` 46, answered by a 46-byte bare acknowledgement.

```
00 00 00 30                       total_len  = 48
00 00 00 2e                       msg_type   = 46 = 13 + 33 slot bytes
00 50 48 52                       sequence
00                                dir = request
<BLN> NUL <supervisor> NUL <BLN> NUL <node> NUL    four routing slots
09 51                             opcode  — and nothing after it
```

So `is_bare_ping`, which tested for a two-byte payload, was **never once true**,
and the frames it was written to name went on being reported as `"unmatched"`.
Nor are they keepalives: they are `AP2_DBCHANGE_*` notifications — a peer
announcing that its point, trend, PPCL, controller or EQS database changed. The
protocol's keepalive is `0x4640 EBLN_PING` (§9.6), which carries a body.

`is_bare_ping` is replaced by `is_dbchange_notify`, which walks the routing
slots to the opcode the way `msg_type_for` already does, and the discard reason
`"bare_ping"` becomes `"dbchange_notify"`.

### The scanner had no tests. It does now

`tests/` at the repository root, and a third CI job. The repository's oldest
and most-used tool was the only one CI never touched, which is how a predicate
that was never true survived. **16 tests**: framing invariants, `msg_type`
derivation, the notification predicate and its negative cases, and an
end-to-end run against the virtual panel.

### `virtual_pxc/`: the fixture was malformed on the way out

Adding an emitter for the notification above meant looking at the one outbound
path the panel had, and it was wrong three ways:

- **Two direction bytes.** Routing was built inline starting with a NUL, and
  then the direction byte was prepended. A conforming client read slot 0 as
  empty, lost the node name, and took its first two characters for the opcode
  (`NODE1` → `0x4E4F`). This is the phantom-NUL defect `_build_routing`'s
  docstring says was fixed; `_push_to` rolled its own and never got the fix.
- **A constant `msg_type`** — the module's own `TYPE_DATA`, marked deprecated
  in the source. The panel that silently drops an inbound frame for a wrong
  header length was **emitting 51 where its slots required 33**.
- Nothing caught it because **nothing consumed a push**.

Every COV notification and every panel-state push was affected. `verify.py` now
holds the panel's own outbound frames to the same four invariants as its
responses, and **`push_dbchange()`** sends an unsolicited notification on the
already-open session — refusing any DBCHANGE opcode never actually observed,
because a fixture that emits an unattested frame teaches the wrong wire format.

Self-verification: **24 PASS, 1 PARTIAL, 3 ABSENT, 0 FAIL** (was 19/1/3/0).

### `p2_scanner.py`: an unknown TEC application invented 61 points

`get_point_table()` ended in an unconditional fallback. Whatever the
application number, if the catalog did not know it the function returned
`COMMON_POINTS` — so `get_point_table(1)` and `get_point_table(424242)` each
answered with the same **61 points**, indistinguishable from real catalog data.

The embedded catalog covers **1,070 applications numbered 20–6797**. Any TEC
running something outside that set got a plausible point list belonging to no
device. Downstream, the bridge's manifest builder typed **all 61 as analog
BACnet objects**, because the rich metadata that would have said otherwise does
not exist for an application the catalog has never heard of — so a supervisor
would have been pointed at 61 objects per device that read as nothing.

The comment above those tables has always said they are used *"ONLY when the
full catalog cannot be loaded at all"*, and the docstring called that path
*"dead for normal installs"*. It was neither. An unknown application now
returns an **empty table**, and the hardcoded tables serve applications
2020–2027 and only when no catalog is reachable. A caller that gets nothing
logs a skip; a caller that gets a plausible list builds on it.

Found by the mechanical mapping diff below, not by reading the function.

### The BACnet mapping cross-check (`AUDIT_PLAN` §14 step 4)

The bridge's point-type map and the vendor's own, diffed rather than read:

| | |
|---|---|
| the bridge | `P2_TYPE_TO_BACNET`, **4 entries** — analogInput, analogValue, binaryInput, binaryValue |
| the vendor | `BAC_Point_Base`, **9 arms** tagged with the BACnet object-type enumeration: AI 0, AO 1, AV 2, BI 3, BO 4, BV 5, **MI 13, MO 14, MV 19** |

Five P2 point types carry more than two states — `LOOAP` and `LOOAL`
(OFF/ON/**AUTO**), `LFSSL` and `LFSSP` (STOP/SLOW/FAST), and `LENUM` (six) —
and the vendor ships a typed BACnet add form for every one. **Multi-state
appears nowhere in `bridge/`.** Measured across all 1,070 catalogued
applications and 181,170 points, none of those five types occurs in a TEC
application table, so nothing is lost today; the gap is real and currently
unexercised, which is the honest way to state it.

### `p2_scanner.py`: a real unit lost to a placeholder

`looks_like_units()` was fixed earlier for accepting too little. The remaining
half was **which** candidate to take when a body carries more than one. It took
the last, and one real body in sixty holds `DEG F` and then, further on, a lone
`?` — so the unit was thrown away and a placeholder reported.

It now prefers a candidate the embedded catalog recognises and falls back to the
last otherwise. The fallback is deliberate: `eng_units` is a `TEXT_` field an
engineer types into, so a site can hold a unit string that ships in no catalog
and discarding those is the defect from the other direction. **Prefer what is
known; never drop what is merely unknown.**

Measured over the same sixty real `0x0981` bodies: catalog-recognised units
**36 → 37**, everything else unchanged — same fifteen empty, same fifty-nine
values.

Worth recording because a plausible-sounding fix was **rejected** here: the
strings that look wrong in that field — `OCCUPIED`, `ENTHALPY` — sit in exactly
the same structural slot as a confirmed `DEG F` (name ×3 each followed by an
empty TLV, description, units, trailing empty). The panel really does hold them.
`STAGES`, also suspected, **is in the vendor catalog**. A filter would have
discarded real panel data.

### `PROTOCOL.md` §6.1.1: the minimum frame size

The observed range was given as **31 to 1,622 bytes**. True, and misleading:
that 31 is **this project's own malformed probe traffic** — frames carrying a
hard-coded `msg_type` of `0x33` against slots implying 17 to 29, among the 736
exceptions §6.2.2 already attributes to our two research addresses. The
smallest **well-formed** frame from a supervisor or a panel anywhere in 623,164
trusted frames is **41 bytes**. The section now says so, and states plainly
that no bare-opcode frame exists.

## v2.10.0 — a virtual panel, a BACnet bridge, and 9.3% of PPCL (2026-09-18)

### Two new components: a virtual PXC, and a P2 → BACnet bridge

**[`virtual_pxc/`](virtual_pxc/)** — a virtual APOGEE panel to develop and test a
P2 client against, with no hardware. What makes it worth pointing a client at is
that it **refuses what a real panel refuses**:

- `msg_type` is validated as `13 + the total bytes of the four routing slots`
  (§6.2), and a frame whose value disagrees with its own slots is **dropped
  silently** — the failure mode that is hard to find in a building and trivial to
  find here. `0x33` and `0x34` get no special treatment; they are two lengths,
  not two dialects.
- An unimplemented opcode gets `not_found`, not a synthetic success.
- `drop_connections()` and `refuse_connections(n)` exercise a client's reconnect
  and backoff paths, which are usually the least-tested code it has.

It ships **`reference_shapes.json`**: the structure of real captured panel
responses across **70 opcodes and 148 distinct structures**, with lengths and
contents stripped so it is publishable. `verify.py` checks the panel against
`PROTOCOL.md`'s frame invariants, against that reference, and against the
protocol document's own virtual-PXC capability list — and reports what it does
**not** model rather than passing over it.

**[`bridge/`](bridge/)** — a read-only P2 → BACnet/IP bridge. Every P2 point
becomes a BACnet object, so any BACnet supervisor can read APOGEE PXCs. It is a
separate application: `bacpypes3` is declared in `bridge/requirements.txt` and
never at the repository root, and the scanner does not import it, so cloning
this repository to use the scanner alone still installs nothing.

### First CI in this repository

`.github/workflows/tests.yml` runs both suites on Python 3.10–3.13. The jobs are
separate on purpose: the virtual PXC installs only pytest, which is the check
that the dependency direction has not been reversed.


### `p2_scanner.py` — eleven real engineering-unit strings were being discarded

`_parse_enum_points_response` decides whether a candidate TLV is an engineering
unit with `looks_like_units()`, and that function accepted a space-containing
string **only** when it started with `DEG `, `deg ` or `IN `:

```python
if ' ' not in s: return True
if s.startswith('DEG ') or s.startswith('deg '): return True
if s.startswith('IN '): return True
return False
```

Eleven unit strings in the shipped TEC catalog fail that test — `SQ. FT` (336
occurrences), `PCT RH` (108), `KVA H` (21), `KW H` (21), `SQ FT` (18),
`10K HR`, `V MA`, `PCT KW`, `K OHM`, `CU FT`, `ERR CD`. **522 occurrences, 2.0%
of the catalog**, dropped silently: the point still reports its value, with an
empty unit string. Anything downstream that maps units — a BACnet bridge, a
trend export, a display — sees nothing to map.

The fix is not a longer allowlist. **The scanner already embeds the catalog**,
so the set of real unit strings is known rather than guessable. `looks_like_units`
now consults `known_unit_strings()` first and keeps the shape heuristic only as
a fallback for a unit the catalog does not carry.

Measured against 60 real `0x0981` response bodies: unit extraction is identical
except that **two records that previously returned an empty unit now return
`PCT RH`**. No other value changed.

Found by making a mock panel emit the real `0x0981` body shape rather than an
invented one — the mock sent `PCT RH` in the exact framing a panel uses and the
parser returned `''`.

## v2.9.1 — the correction to the correction (2026-09-18)

### `PROTOCOL.md` §14.3 — `EQUAL` and `LESS` are reserved words after all

v2.9.0 shipped a correction removing `EQUAL` and `LESS` from the PPCL
reserved-word set, on the reasoning that they were the description column of a
two-column vendor table read as tokens. **That correction was wrong**, and if
you built a tokenizer or a linter from it, its reserved-word list is two
entries short.

Both words appear in two independent vendor *enumerations* — the Insight
Program Editor's reserved-word page and 125-1896 Rev. 5 chapter 5 — each in its
own alphabetical cell, on pages that have no description column at all. The
Program Editor page is 224 cells and not one of them contains prose.

What no edition of this table had right: they are reserved **names**, not
operators. No vendor source documents a syntax for either, and in Siemens' own
84-program PPCL application library both occur only inside comment lines. A
tokenizer that maps `EQUAL` onto `EQ` invents an operator. §14.3 now carries
them in a row of their own.

`ARC` → `ATN`, the other half of the v2.9.0 correction, is unaffected and
confirmed from two directions.

### §14 — resident points were four different kinds of thing

The resident-point table filed `LOCAL`, `TOTAL`, `LOW` and `FAILED` alongside
`TIME` and `CRTIME`. `LOCAL` is a **declaration keyword** and is never a value a
program reads; `TOTAL` is a **function**; `LOW` and `FAILED` are **status
values** compared against. A client resolving all of them as resident points
reads those statements wrong. The occurrence counts were also recounted by
syntactic position rather than by regex — the old figures counted a word
appearing as a dotted segment of a *point name* as a reference to the resident
value.

### `p2_scanner.py` — a withdrawn model surviving in a docstring

`_parse_handshake_response` still drew the frame as
`[4B length BE] [4B msg_type=0x33/0x34] ...`, which reads as a fixed pair of
class bytes. `msg_type` is a header length, `13 + the total bytes of the four
routing slots`; `0x33` and `0x34` are simply the two lengths that capture's node
names produced. No behaviour change — the code has computed the field since
1.4.0.

## v2.9.0 — the correctness pass (2026-09-18)

Nine defects in shipped code, and a corpus recount that moved every aggregate
figure in `PROTOCOL.md`. If you are running 2.8.2, the first four are producing
wrong output on your captures right now.

### `p2.lua` — the Info column was inverted on the header-length check

Every well-formed **request** frame rendered `[hdrlen 51/=53]`, and a frame
whose header length was **exactly 2 too large rendered clean**. The comparison
used an offset already advanced past the opcode, so `hdrlen == off + 2` compared
equal precisely when `hdrlen` was itself 2 too large.

+2 is what you get by counting the `u16` opcode into the header length — the
most likely way to get that field wrong. So the dissector cried wolf on correct
traffic and stayed silent on the one error it exists to catch. On a 17,926-frame
reference capture that is ~9,500 false warnings.

The `p2.hdr_len_mismatch` *field* was always correct; only the column lied. A
filter-driven workflow was unaffected.

### `p2.lua` — a `0x00`-typed string TLV truncated or corrupted a record

`PROTOCOL.md` §8.1 defines `TEXT_` as `<textType:u8> <textLen:u16>`, and
textType is `0x00` on 24 of 113,523 corpus TLVs — all empty strings, across
`eng_units`, `name`, `suffix` and `descriptor`. Three anchored decoders tested
`~= 0x01` and **`break`**, one tested `== 0x01` and skipped the advance:

- a COV point whose empty **suffix** was `0x00`-typed reported its value as
  **`9.24856986e-44` instead of `72.25`** — the suffix header read as the `f32`.
  A plausible-looking wrong point value, silently.
- a COV point whose **name** was `0x00`-typed decoded **zero points**: the
  `break` abandoned the whole record, not that one point.
- `dissect_roster` and `dissect_identity` truncated the same way.

Fixed at the anchored sites. The unanchored *scanning* loops deliberately stay
strict — widening those as well replaced point names with empty strings in 976
of 82,294 corpus rows, because in a loop that advances a byte on no match every
`0x00` becomes a TLV candidate.

### `p2.lua` — the node-name table walked past its own count

`dissect_roster` ignored `r_count` and walked to the end of the buffer. The
table ends with four zero bytes; the old textType test stopped there for the
wrong reason, so fixing that exposed a blank 15th node. It now walks the
declared count.

### `analyze_pcap.py` — every retransmitted frame was counted twice

Segments were appended in arrival order, so a retransmission's bytes entered the
stream again and its frames were parsed again. **Every count the tool printed
was inflated** — on the reference capture, 18,056 frames reported against 17,924
real, `0x0274` reading 4,498 against 4,486.

Segments are now placed at their offset from the connection's lowest sequence
number, which handles retransmission, reordering and partial overlap the way a
receiver does. Duplicate and missing bytes are reported rather than absorbed.

### `analyze_pcap.py` — 558 known opcodes were reported as unknown

It hand-maintained 80 opcode names beside `p2_data.py`'s generated 638, under a
comment asking a person to mirror new ones in by hand. Anything outside the 80
printed as `*** UNKNOWN *** <-- NEW`. Worse, **73 of the 80 labels contradicted
the catalog** — pre-enumeration guesses the AP2 name set later overturned.
`p2_data` is now the only name source; seven labels carrying a wire
*observation* rather than a name are kept as notes.

### `PROTOCOL.md` — low figures, and a procedure that contradicted itself

**Corpus recount.** The project's raw reader silently discarded half-connections
whose TCP port had been reused — on one capture, **782 of 3,211 conversations**.
Recounted with three independent tools, which agree exactly:

    trusted frames        621,268 -> 623,164
    direction 0x00        314,273 -> 316,169
    msg_type 0x2E          42,542 ->  44,438
    msg_type == 13+slots  620,532 -> 622,428   still 99.88%
    error codes, 121 captures, 135 of 630 opcodes   unchanged

Every recovered frame is a request with identical BLN slots; both exception
counts are untouched and only the denominators grew.

**§7.3's client procedure** told a reader, in step 2, to "frame it on the
second-channel class matching the peer's generation — `0x2E` legacy, `0x2F`
modern" — three steps before step 5 withdraws exactly that. A wrong `msg_type`
is **dropped, not rejected**, so following step 2 gives no error, just a peer
that never answers.

**§1's Summary** described the string TLV as `01 00 <len> <ascii>` — the
one-byte-length form §8.1 withdraws — on the document's first screen.

**§8.2's scope-tag example** leads with `scope_byte=0x23`; a plain read uses
`0x00` (17,650 requests against 1,061). The example now says so.

### Provenance

Evidence tags `[F]` (firmware-attested) and `[C]` (codec-attested) are collapsed
into `[S]`, and ~45 sentence-level attributions moved to neutral specification
vocabulary. **No claim changed** — what changed is whether the text says how a
fact was learned. `PROTOCOL.md` is now generated from an internal source
document; edit that and regenerate.

### Testing

The repository had no tests. It now has, in the analysis harness rather than the
package: a committed-vs-edited field diff for `p2.lua` over the corpus (82,294
rows); synthetic captures for the header-length and TLV cases the corpus does
not contain; a three-way frame census across the raw reader, the dissector and
the analyzer; and a codec built from `PROTOCOL.md` alone whose selftest
round-trips real capture frames — **144,156 frames over three captures, every
one re-encoded byte-identically.**

## v2.9.0 — the `msg_type` correction (earlier in the same cycle)

**The "message class" model is withdrawn.** Earlier entries in this file, and
releases up to 2.8.2, described the `u32` at frame offset 4 as a message class
taking six values in legacy/modern pairs chosen by a panel's firmware
generation, and recommended fingerprinting a panel with `CABINET_DISPLAY`
(`0x010C`) to pick the right one.

That is wrong. **The field is a header length** — `13 + the total bytes of the
four NUL-terminated routing slots` — so it is a sum of node-name lengths and
differs from site to site. The six values are simply what one site's names
summed to. **Compute it; never choose it.** A wrong value is dropped silently by
the panel, which is why guessing appeared to work.

Consequences already in the tree: the dialect probe, its per-host cache and the
build-tag fast path are removed from the scanner; `p2.lua` shows the computed
length beside the wire value and flags a mismatch; `firmware_registry.py` keeps
only the platform/string-encoding role of the build tag. Those earlier entries
are left as written, since a changelog is a record of what was believed at the
time.

Full account in `PROTOCOL.md` §6.2, with §6.6 recording the withdrawal and
§6.2.5 listing which observations from the old model survive.

Release notes for the P2 dissector, scanner and protocol reference.
The current release is summarised at the top of [README.md](README.md).

> Entries below v2.7 are kept as written at the time. Figures in them reflect
> what was believed then; where a later release corrected one, the correction is
> in that release's entry and in `PROTOCOL.md`.

## v2.8.2 — the decode side

- **A request may carry a zero-length body**, and 220 in the corpus do — `0x010C`
  (163x), `0x4633 EBLN_REPL_NOTIFY` (22x), `0x0951 DBCHANGE_POINT` (11x) and the
  rest of the `DBCHANGE` family. It is the natural encoding of a parameterless
  operation: the `u16` opcode is the whole message. An encoder must be willing to
  emit an ASDU of length zero and a decoder must accept it as complete rather
  than truncated.
- **The family band is structural, not descriptive.** §9.4 said the opcode's high
  byte "loosely tracks" the family. The supervisor's command factory selects a
  subclass by switching on `opcode & 0xFF00`, so the band is a real
  classification in the implementation.
- Decode confirmed as the mirror of encode: the decoder is handed `buf+2` and
  `total-2`, so the two reserved opcode bytes of v2.8.1 are established from the
  receive direction too.

## v2.8.1 — the segmentation ceiling

- **A segment is 16,384 bytes; the encoder may fill 16,382.** The two bytes held
  back at the head are the `u16` function code, written after the body is
  encoded — which is why the wire carries the opcode immediately before the body
  and why `total_length` counts it. An implementer reading a body is reading the
  encoder's `buf+2`.
- **Reassembly is a cursor against a declared total**, not a negotiation: each
  mapped segment copies `n` bytes and advances the cursor, and the last segment's
  length is `total - cursor`. The sender knows the total before it begins.
- **The ceiling is not exercised by anything captured.** No body in the corpus
  exceeds 16,382 B — largest complete 1,570 B, largest declared 12,073 B — so a
  client may size a receive buffer at 16 KB with confidence, while the on-wire
  form of a *multi-segment* exchange remains unobserved and stays `[OPEN]`.
- §4's segmentation open item goes from "not pinned" to "pinned in the encoder,
  unobserved on the wire".

## v2.8.0 — the two EQS records, decoded in full

- **`0x0989` mode schedule: eleven fields, not five.** `entry_ID`,
  `entry_enabled`, `mode`, `occurrence`, `scheduled_days`, `start_date`,
  `end_date`, `start_time`, `stop_time`, `days_spanned`, `exclusive`, and a
  trailing `state_text_id`. Validated on every captured record: both dates carry
  a weekday byte that must match their own date, both times must be real, the
  booleans must be 0/1, and the record must consume the body exactly.
- **`scheduled_days` is a bitmask**, bit 0 = Sunday. `0x3E` is Mon–Fri, `0x41` is
  Sun+Sat, `0x7E` is Mon–Sat.
- **`0x0987` zone: the lead `u16` is a count of names.** What an earlier edition
  called "the name again after a two-byte separator" is the second
  `Team_response` entry, whose own `name_space` supplies those two bytes — and
  the pair is the zone's **system name and user name**, not a duplicate.
- **The trailing `u16` on both records is a state-text-table id.** It had been
  an unexplained two-valued field through four wrong readings. It is constant
  per zone and identical across both opcodes.
- **A third point-type numbering**, and the most dangerous: a current supervisor
  product ships a dense 1..16 renumbering of the L-type mnemonics beside the
  sparse wire codes, spelled identically. Six of fifteen disagree.
- **How the `0x09xx` bank is organised** — section × transfer direction × record
  state — and why an opcode cannot be computed from a section index.

## v2.7.1 — the error table, corrected

- **26 of the 42 error names were wrong, and it was one defect.** The table was
  **shifted by one entry** against the vendor's field-panel error catalog, from
  `0x0007` through `0x0210` and again across the FLN band, so each code carried
  the name belonging to the next code up. The `_v2` suffixes the old table used
  (`already_exists_v2`, `value_out_of_range_v2`) are the tell: the duplicate
  names the shift produced were suffixed rather than investigated.
- **One consequence was behavioural, not cosmetic.** `0x0E11` was named
  `already_exists` and `p2_scanner` treated it as a **success**, so a failed FLN
  point-add was reported as having worked. `0x0E11` is *FLN invalid drop number*;
  the code that means already-exists is `0x0009`, which had been left unnamed.
- **`0x0E10`–`0x0E17` is the FLN error band** — field-level faults, not the
  record-state rejections the old table implied.
- **`not_supported` (`0x00AC`) is revision-dependent.** It also covers a function
  code that is specific to a different firmware revision, so a panel answering it
  does not prove the opcode is unimplemented.
- The table is now **generated** rather than hand-maintained, and `PROTOCOL.md`
  §7.2.2 records the correction rather than quietly replacing it.

## v2.7 — the operand, the paging model, and four decoded records

- **Opcodes carry operands.** A run of consecutive opcodes is usually one
  operation with a small parameter (filter, state, phase, bus number,
  boolean) encoded in the opcode instead of the body. 55 families covering
  146 opcodes are named by the dissector (`p2.operand`) and the scanner.
- **Range-and-resume paging** documented for every bulk read (§10.2.3), with
  the four selector encodings and the out-of-range resume sentinel.
- **Four record types decoded and dissected**: the enhanced-alarm definition
  (`0x0983`) and the three equipment-scheduling records (`0x0987`, `0x0988`,
  `0x0989`), including the ISO-numbered weekday byte the dissector uses as an
  alignment self-check.
- **The CPI tier corrected**: the wire opcode is chosen while the request is
  encoded, so no 1:1 operation↔opcode map exists; the object field at `+0x06`
  is the CPI function code, closing a standing open item.
- **Accuracy audit of `PROTOCOL.md`**: the §9.5 catalog is generated from the
  data the tools ship, every corpus figure derives from one reproducible
  census (206,050 trusted frames, 104,752 requests, 125 wire-observed
  opcodes across 85 captures), and the table of contents is complete.

## v2.6 — accuracy pass

The `0x29` / `0x2A` carrier labels are corrected: they were
named "peer maintenance" and "peer COV-subscribe," and the corpus establishes neither
function. They are now **session carrier** and **peer-session carrier (panel↔panel)**,
matching PROTOCOL.md §6.2; both carry the `EBLN_PING` (`0x4640`) identity exchange.
Error code `0x0E12` is named `record_state_rejected (unconfirmed)` — observed a handful
of times, adjacent to already-exists, precise meaning not pinned — and opcode `0x0030`
`AP2_SET_GLOBAL_DATA` is added. **Bug fix:** the error-tail read guarded on frame
length rather than on the post-slot offset, so a truncated `dir==0x05` frame could
render two header bytes as a phantom error code (observed: a 13-byte frame reporting
"ERROR 0x0105"). It now guards on the slot offset.


## v2.5 — response correlation + more body decoders

Responses carry no opcode on the
wire (only requests do) but echo their request's sequence; the dissector now keeps a
per-TCP-stream `{sequence → opcode}` map and **labels and decodes responses** — the
`CABINET_DISPLAY` firmware banner (revision / platform / build date / node-site-BLN), the
value responses (point name + engineering-units + value), and the identity exchange. New
request decoders too: the addressing family — point read/command, COV enable/disable,
trend, bulk upload (scope tag + name + suffix + commanded value) — and `ALARM_PRINT`
(`0x0508`) with its value block and three 8-byte event timestamps. Validated with zero
Lua errors across a ~530k-frame corpus.


## v2.2 — message-class model corrected from fleet captures

The message classes are
legacy/modern **pairs chosen by a panel's firmware generation, not by direction**:
data `0x33` (legacy) / `0x34` (modern); second channel `0x2E` / `0x2F` (identity +
DB-change/replication records + alarm prints); peer carriers `0x29` / `0x2A`
(panel↔panel, visible only from a panel-side mirror). Fingerprint a panel with
`CABINET_DISPLAY` (`0x010C`) and pick the dialect from its firmware. Also: COV
condition byte0/byte1 (priority/control-status) wire-confirmed; sequence is
per-(peer,channel) with gaps (not one global counter); `UPL_ALL_*` continuation is
application-layer cursoring, not a frame more-follows bit; event timestamps are 8 bytes
(`yr-1900, mo, day, day-of-week, hr, min, sec, cs`).


## v2.1 — wire-verified rebuild

Opcode names corrected to the full
set; the framing model fixed (the opcode is read only on request frames, at its true
variable offset); accurate body decoders for the common operations; per-opcode
*expected-body schema* notes; and the old UDP/10001 "multicast presence beacon"
decoder **removed** (it was a misattribution of unrelated gateway traffic — see
*Correctness notes*).
