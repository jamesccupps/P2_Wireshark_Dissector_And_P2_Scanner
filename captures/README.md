# Sample capture

`p2_virtual_pxc_sample.pcap` — 112 frames, 12,603 bytes, three TCP sessions on
port 5033. Open it with `p2.lua` installed and filter on `p2`.

```
sha256  a6b21fee5bfc05ac7b14e487758b18b48235f4acb4711e259e51d291fe33109d
```

## What it is, and what is synthetic

**The P2 bytes are real.** They are what `p2_scanner.py`'s own client code and
the [virtual PXC](../virtual_pxc/) put on the socket while talking to each
other, recorded write by write on both sides. Recording the writes rather than
the client's reads keeps the segment boundaries a client and a panel actually
produce.

**The wrapper is synthetic.** The Ethernet, IPv4 and TCP headers are built by
`make_sample_capture.py`, because a real loopback capture needs a capture driver
and privileges, and would carry `127.0.0.1`. Checksums are computed, and
Wireshark verifies every one of them. Frame times run from 2026-01-01 00:00 UTC
at a fixed spacing, so regenerating the file produces the same bytes.

**Nothing in it comes from a real site.** The addresses are RFC 5737
documentation addresses (`192.0.2.10` client, `192.0.2.20` panel) with locally
administered MACs. Every name comes from `virtual_pxc/fixtures.json`: BLN
`MYBLN`, panel `NODE1`, site `BUILDING1`, devices `VAV001`/`VAV002`/`FCU001`,
standard TEC point names. The scanner identifies itself as `P2SCAN-LAP|5033`.

A real capture can't stand in for this one. The BLN name is in the first
routing slot of every frame, and IP/MAC anonymizers don't touch payload strings.

## What's in it

| exchange | opcode | shows |
|---|---|---|
| session handshake | `0x4640 AP2_EBLN_PING` | the identity block; once per session |
| panel identity | `0x010C AP2_CABINET_DISPLAY` | revision, platform, names |
| point read | `0x0271 AP2_COV_ENABLE` | the scanner's read **is** a COV subscription; the response carries the point |
| read of a point that does not exist | `0x0271` → error | a direction-`0x05` error response |
| unsolicited push | `0x0951 AP2_DBCHANGE_POINT` | a frame the client did not ask for, arriving mid-session |
| device browse | `0x4200 AP2_CONTROLLER_LOG` → error | `not_found` |
| point enumeration | `0x0981 AP2_UPL_ALL_POINT` | a cursor walk, ending in the `not_found` that marks the end |
| FLN enumeration | `0x0986 AP2_UPL_ALL_TEC` | the same walk over field devices, on its own session |
| revision string | `0x0100 AP2_REV_STRING` | the legacy identity read, on its own session |

## Check it yourself

```
tshark -r p2_virtual_pxc_sample.pcap -o ip.check_checksum:TRUE -o tcp.check_checksum:TRUE -Y "tcp.checksum.status != 1"
tshark -X lua_script:../p2.lua -r p2_virtual_pxc_sample.pcap -Y p2
```

The first should print nothing. The second should print 47 frames, none
malformed.

## Regenerate

```
python captures/make_sample_capture.py
```

It drives the fixture panel and rewrites the file. The output is deterministic,
so a regeneration that changes the hash above means the scanner or the fixture
changed what they put on the wire.
