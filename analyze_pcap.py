"""analyze_pcap.py — comprehensive opcode / error-code / direction-byte
inventory for a captured pcap. Walks every TCP segment, reassembles P2
frames, and tallies what we see.

Surfaces:
  - All opcodes by dir byte (req/resp/err) and by destination port. Note:
    port is reported for reference only — message direction is determined by
    traffic direction (panel->supervisor vs supervisor->panel), NOT by port
    number. 5033 is the canonical P2 port; 5034 is a site-specific second
    supervisor listener (seen when a second supervisor product is co-installed
    on one management station and bumps off 5033 to avoid a collision).
  - All error codes seen
  - All msg_types seen
  - Frame-size distribution per opcode (catches "weird big frame" outliers)
  - Sample raw payloads for each unknown opcode
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
from collections import Counter, defaultdict

# Console output uses Unicode formatting chars (→, ──, etc.) for readability.
# Windows defaults to cp1252 in cmd.exe / PowerShell, which crashes on these.
# Reconfigure stdout/stderr to UTF-8 so the script works on stock Windows
# without requiring users to set PYTHONIOENCODING themselves. Python 3.7+.
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except (AttributeError, OSError):
    pass  # already UTF-8, or stdout was redirected to something that can't be reconfigured


# Short labels for the census columns. These are a DISPLAY GLOSS, not the
# opcode catalog: "ValuePush/COV" reads better than "AP2_COV_ANNUNCIATE" when
# you are scanning a column of counts, and that is all they are for.
#
# What is KNOWN is decided by `p2_data.OPCODE_NAMES` (638 entries, generated;
# the same table behind PROTOCOL.md §9.5 and p2.lua's P2_DATA block) via
# `opcode_label()` below. This list used to be the catalog, hand-maintained at
# 80 entries with a comment asking a person to mirror new opcodes into it by
# hand — so 558 opcodes this repository already names were reported as
# "*** UNKNOWN *** <-- NEW", which is precisely the drowning the comment warned
# about. Adding a gloss here is optional and affects only how a line reads.
WIRE_NOTES = {
    # Not names -- OBSERVATIONS, kept because the AP2 function-code name cannot
    # carry them and they were established from the wire. Everything else that
    # used to live here was a pre-enumeration guess at what an opcode does; 73
    # of those 80 labels contradicted the catalog outright (e.g. 0x0271
    # "ReadExtended(legacy)" against AP2_COV_ENABLE), so they are gone and
    # `p2_data` is the single name source, as it is for PROTOCOL.md §9.5 and
    # p2.lua. Full account in the findings, §115.
    0x5354: "constant body 53 54 01 00 04 SYST 00 3F FF FF FF; always 0x0003",
    0x098B: "constant body 09 8B 00 01 00 FA 00 00; always 0x0003",
    0x0204: "returns 0x0E11 if the object already exists",
    0x0294: "small request, 222 B preallocated response",
    0x4220: "222 B preallocated; '00 10' selector at the sentinel (single sample)",
    0x4221: "273 B preallocated",
    0x099F: "5 B body 09 9F 00 04 XX; indices 0xFF and 0x00-0x04 walked",
}

# Full 37-code catalog per PROTOCOL.md §7.2.2; kept in sync with
# p2.lua's STATUS_ERRORS and p2_scanner._P2_STATUS_ERRORS.
KNOWN_ERRORS = {
    0x0001: "no_memory_available (E1)",
    0x0002: "invalid_command (E2)",
    0x0003: "not_found (E3)",
    0x0004: "priority_too_low (E4)",
    0x0005: "no_change (E5)",
    0x0007: "point_failed (E7)",
    0x0008: "out_of_service (E8)",
    0x0009: "already_exists (E9)",
    0x000A: "trend_already_exists (E10)",
    0x000B: "value_unchanged (E11)",
    0x000C: "value_out_of_range (E12)",
    0x000D: "not_hostcaller_node (E13)",
    0x0016: "line_not_traced (E22)",
    0x0028: "invalid_dst_pair (E40)",
    0x0040: "invalid_report_id (E64)",
    0x0065: "command_not_supported (E101)",
    0x0080: "invalid_user_id (E128)",
    0x0081: "invalid_password (E129)",
    0x0082: "user_accounts_database_full (E130)",
    0x00AB: "coldstart_required (E171)",
    0x00AC: "not_supported (E172)",
    0x00B7: "too_many_framing_errors (E183)",
    0x00B8: "scu_no_answer (E184)",
    0x00F9: "invalid_point_address (E249)",
    0x00FA: "failed_io_device (E250)",
    0x00FE: "io_timeout (E254)",
    0x0200: "monitor_list_full (E512)",
    0x0202: "flt_transfer_in_progress (E514)",
    0x0203: "flt_transfer_killed (E515)",
    0x0205: "tec_not_added (E517)",
    0x0206: "connection_lost (E518)",
    0x0207: "warm_started (E519)",
    0x0209: "protocol_error (E521)",
    0x0210: "timeout (E528)",
    0x0E10: "fln_invalid_fln_number (E3600)",
    0x0E11: "fln_invalid_drop_number (E3601)",
    0x0E12: "fln_device_failed (E3602)",
    0x0E13: "fln_invalid_point_number (E3603)",
    0x0E14: "fln_physical_point_failed (E3604)",
    0x0E15: "physical_point_not_commandable (E3605)",
    0x0E16: "fln_value_out_of_range (E3606)",
    0x0E17: "fln_application_invalid_for_device (E3607)",
}

# There is no message-type table. The u32 at offset 4 is a HEADER LENGTH --
# 13 + the total bytes of the four NUL-terminated routing slots
# (PROTOCOL.md 6.2) -- so its value is a sum of node-name lengths and varies by
# site. This dict used to name 0x2E/0x2F/0x33/0x34 as CONNECT / ANNOUNCE and
# legacy / modern "dialects"; those are the four values one site's names
# produced. A census of them is a census of that site's naming, which is worth
# printing as such and worth checking against the slots.
MSG_TYPES = {}

DIR_BYTES = {0x00: "Request", 0x01: "Success", 0x05: "Error"}


DECODE = False
DUMP_LIMIT = 0

try:
    import p2_body
except ImportError:                        # the structure catalog is optional
    p2_body = None

try:
    import p2_data                         # the generated opcode catalog
except ImportError:
    # It is the ONLY opcode name source now, so without it every opcode
    # reads as unknown. It ships in this directory; if it is missing, put it
    # back rather than reading the "NEW" column.
    p2_data = None

def opcode_label(op):
    """Display label, or None if the opcode is genuinely not in the catalog."""
    name = p2_data.opcode_name(op) if p2_data is not None else None
    if not name:
        return None
    note = WIRE_NOTES.get(op)
    return "%s [%s]" % (name, note) if note else name


# --decode collectors
decode_stats = Counter()
decode_errors = Counter()
decode_dump = []


def decode_body(opcode, body):
    """Walk a request body against its declared structure and tally the result."""
    if p2_body is None:
        return
    r = p2_body.decode(opcode, "req", body)
    if r.struct is None:
        decode_stats["no structure declared"] += 1
        return
    if r.padded:
        decode_stats["decoded, zero-padded to a fixed size"] += 1
    elif r.error is None:
        decode_stats["decoded, whole body consumed"] += 1
    elif r.error.endswith("does not account for"):
        decode_stats["decoded, trailing bytes"] += 1
    elif r.truncated:
        decode_stats["truncated at a field boundary"] += 1
    else:
        decode_stats["stopped early"] += 1
        decode_errors[r.error[:70]] += 1
    if len(decode_dump) < DUMP_LIMIT:
        decode_dump.append((opcode, r))


def parse_routing(payload):
    """Skip 4 null-terminated strings, return body offset."""
    if not payload:
        return None
    off = 1
    for _ in range(4):
        end = payload.find(b"\x00", off)
        if end < 0:
            return None
        off = end + 1
    return off


# ─── State ──────────────────────────────────────────────────────────────────

# (peer_a_ip, peer_a_port, peer_b_ip, peer_b_port) ordered → reassembly buffer
streams = defaultdict(bytearray)

opcode_counts = Counter()      # opcode → count
opcode_by_dir = defaultdict(Counter)  # dir_byte → opcode → count
error_codes = Counter()
msg_types = Counter()
next_seq = {}                 # half-connection -> next expected stream offset
retransmit_bytes = [0]        # duplicate bytes trimmed, for the report
gap_bytes = [0]               # bytes missing from the capture, for the report
unknown_opcode_samples = defaultdict(list)
opcode_sizes = defaultdict(list)
opcode_by_port = defaultdict(Counter)  # tcp_port → opcode → count

# Track conversation directionality: since TCP is bidirectional, we use
# (src_ip, src_port, dst_ip, dst_port) as the stream key — that gives one
# entry per direction.
# Stash up to 3 sample bodies for each unknown opcode.


def process_p2_frame(frame, src_ip, src_port, dst_ip, dst_port):
    if len(frame) < 12:
        return
    total_len, msg_type, seq = struct.unpack(">III", frame[:12])
    msg_types[msg_type] += 1

    payload = frame[12:total_len]
    if len(payload) < 2:
        return

    dir_byte = payload[0]
    body_off = parse_routing(payload)
    if body_off is None:
        return

    body = payload[body_off:]
    if len(body) < 2:
        return

    # Distinguish requests (have opcode) from responses (don't echo opcode)
    if dir_byte == 0x00:
        # Request — first 2 bytes after routing are the opcode
        opcode = struct.unpack(">H", body[:2])[0]
        opcode_counts[opcode] += 1
        opcode_by_dir[dir_byte][opcode] += 1
        opcode_sizes[opcode].append(total_len)
        # Tally by destination port for reference only. Port does NOT
        # determine direction or message semantics — direction is the
        # traffic direction (which peer sent the frame). 5033 is the
        # canonical P2 port; 5034 is a site-specific second-supervisor
        # listener, so an opcode appearing on 5034 just means that site
        # runs a co-installed supervisor on the bumped port.
        opcode_by_port[dst_port][opcode] += 1
        if DECODE:
            decode_body(opcode, body[2:])
        if opcode_label(opcode) is None and len(unknown_opcode_samples[opcode]) < 3:
            unknown_opcode_samples[opcode].append({
                "frame_len": total_len,
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
                "body": body.hex(),
            })
    elif dir_byte == 0x05:
        # Error — u16 BE error code immediately after routing
        if len(body) >= 2:
            err = struct.unpack(">H", body[:2])[0]
            error_codes[err] += 1
    else:
        # Success response (0x01) — no opcode echo. Could still detect via
        # heuristic. Unsolicited push frames from a panel (COV / virtual-write
        # / routing events) carry the opcode in the body because they are
        # "requests" semantically from the panel's perspective, and they use
        # dir 0x00 — so they were already counted above. This is true
        # regardless of port: push traffic is port-agnostic (observed on both
        # 5033 and 5034); what marks it as a push is the traffic direction
        # (panel -> supervisor), not the port number.
        pass


def consume_segment(segment_data, src_ip, src_port, dst_ip, dst_port, seq=None):
    """Place segment data in the directional stream and pull complete frames.

    PLACED, not appended. Appending in arrival order parses a retransmission's
    bytes twice -- on this project's reference capture that is 8,677 duplicate
    bytes and 132 phantom frames, and it inflates every count this tool prints.
    `p2raw.half_streams` states the rule: a segment belongs at its offset from
    the connection's lowest observed sequence number, which is the only
    formulation that treats retransmissions, reordering and partial overlaps
    the way a real receiver does.

    p2raw can buffer the whole capture and place bytes absolutely. This streams,
    so it carries the next expected offset per half-connection and trims a
    segment that starts behind it.
    """
    key = (src_ip, src_port, dst_ip, dst_port)
    buf = streams[key]

    if seq is not None:
        nxt = next_seq.get(key)
        if nxt is None:
            next_seq[key] = seq + len(segment_data)
        elif seq < nxt:
            # Behind the write cursor: a retransmission, or a segment that
            # partially overlaps what we already hold. Keep only the new tail.
            skip = nxt - seq
            if skip >= len(segment_data):
                retransmit_bytes[0] += len(segment_data)
                return                       # wholly duplicate
            retransmit_bytes[0] += skip
            segment_data = segment_data[skip:]
            next_seq[key] = seq + skip + len(segment_data)
        elif seq > nxt:
            # A gap -- bytes that were never captured. Any frame spanning it
            # cannot be parsed, and carrying the stale prefix would mis-align
            # everything after. Drop it and resynchronise on the new segment.
            gap_bytes[0] += seq - nxt
            buf.clear()
            next_seq[key] = seq + len(segment_data)
        else:
            next_seq[key] = seq + len(segment_data)

    buf.extend(segment_data)
    while len(buf) >= 12:
        total_len = struct.unpack(">I", bytes(buf[:4]))[0]
        if total_len < 12 or total_len > 65536:
            buf.clear()
            return
        if len(buf) < total_len:
            return
        frame = bytes(buf[:total_len])
        del buf[:total_len]
        process_p2_frame(frame, src_ip, src_port, dst_ip, dst_port)


def main():
    global DECODE, DUMP_LIMIT
    args = [a for a in sys.argv[1:]]
    DECODE = "--decode" in args or any(a.startswith("--decode-dump") for a in args)
    for a in list(args):
        if a.startswith("--decode-dump"):
            DUMP_LIMIT = int(a.split("=", 1)[1]) if "=" in a else 5
        if a.startswith("--"):
            args.remove(a)
    if not args:
        print("Usage: analyze_pcap.py <pcap_file> [--decode] [--decode-dump=N]",
              file=sys.stderr)
        print("", file=sys.stderr)
        print("Inventories opcodes, error codes, frame-size distribution,", file=sys.stderr)
        print("and message-type counts in a P2 capture. Requires tshark on PATH.", file=sys.stderr)
        print("--decode walks each request body against its declared structure", file=sys.stderr)
        print("(needs p2_asdu.py and p2_body.py); --decode-dump=N also prints the", file=sys.stderr)
        print("first N bodies field by field.", file=sys.stderr)
        sys.exit(2)
    pcap = args[0]
    if not os.path.isfile(pcap):
        print(f"[ERROR] pcap not found: {pcap}", file=sys.stderr)
        sys.exit(2)

    # Pull every P2-relevant TCP segment
    print(f"[*] reading {pcap} via tshark...")
    cmd = ["tshark", "-r", pcap,
           "-Y", "(tcp.dstport==5033 or tcp.dstport==5034 or "
                 "tcp.srcport==5033 or tcp.srcport==5034) and tcp.len > 0",
           "-T", "fields",
           "-e", "ip.src", "-e", "tcp.srcport",
           "-e", "ip.dst", "-e", "tcp.dstport",
           "-e", "tcp.seq",            # relative; needed to PLACE the segment
           "-e", "tcp.payload"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        print("[ERROR] tshark not found on PATH. Install Wireshark (which", file=sys.stderr)
        print("        includes tshark) and ensure the install directory is", file=sys.stderr)
        print("        on your PATH.", file=sys.stderr)
        sys.exit(2)
    if proc.returncode != 0:
        print(f"[ERROR] tshark exited with code {proc.returncode}", file=sys.stderr)
        if proc.stderr:
            print(proc.stderr.rstrip(), file=sys.stderr)
        sys.exit(2)
    lines = proc.stdout.strip().split("\n")
    print(f"[*] {len(lines)} TCP segments to process")

    n = 0
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 6 or not parts[5]:
            continue
        try:
            src_ip = parts[0]
            src_port = int(parts[1])
            dst_ip = parts[2]
            dst_port = int(parts[3])
            seq = int(parts[4]) if parts[4] else None
            payload = bytes.fromhex(parts[5].replace(":", ""))
        except (ValueError, IndexError):
            continue
        consume_segment(payload, src_ip, src_port, dst_ip, dst_port, seq)
        n += 1

    print(f"[*] processed {n} segments")
    if retransmit_bytes[0] or gap_bytes[0]:
        print(f"[*] {retransmit_bytes[0]} duplicate bytes trimmed "
              f"(retransmissions / overlap), {gap_bytes[0]} bytes missing from "
              f"the capture")
    print(f"[*] frames extracted (msg_types): "
          f"{sum(msg_types.values())}\n")

    # ─── Output ─────────────────────────────────────────────────────────────
    print("=" * 70)
    print(" HEADER LENGTHS (msg_type = 13 + slot bytes, PROTOCOL.md 6.2)")
    print("=" * 70)
    for mt, cnt in msg_types.most_common():
        print(f"  {mt:>5d} (= 13 + {mt - 13:>3d} slot bytes) {cnt:>8d}")

    print("\n" + "=" * 70)
    print(" REQUEST OPCODES (dir=0x00)")
    print("=" * 70)
    for op, cnt in opcode_counts.most_common():
        label = opcode_label(op)
        name = label or "*** UNKNOWN ***"
        marker = "" if label else "  <-- NEW"
        sizes = opcode_sizes[op]
        if sizes:
            sz = f"sizes {min(sizes)}–{max(sizes)} avg {sum(sizes)//len(sizes)}"
        else:
            sz = ""
        print(f"  0x{op:04X}  {name:<46s}  {cnt:>6d}  {sz}{marker}")

    print("\n" + "=" * 70)
    print(" REQUEST OPCODES — BY DESTINATION PORT")
    print("=" * 70)
    for port, opcodes in sorted(opcode_by_port.items()):
        print(f"\n  → port {port}:")
        for op, cnt in opcodes.most_common():
            name = opcode_label(op) or "UNKNOWN"
            print(f"    0x{op:04X}  {name:<46s}  {cnt:>6d}")

    print("\n" + "=" * 70)
    print(" ERROR CODES (dir=0x05)")
    print("=" * 70)
    for ec, cnt in error_codes.most_common():
        name = KNOWN_ERRORS.get(ec, "*** UNKNOWN ***")
        marker = "" if ec in KNOWN_ERRORS else "  <-- NEW"
        print(f"  0x{ec:04X}  {name:<25s}  {cnt:>6d}{marker}")

    print("\n" + "=" * 70)
    print(" UNKNOWN OPCODES — SAMPLE PAYLOADS")
    print("=" * 70)
    if not unknown_opcode_samples:
        print("  (none — all opcodes accounted for)")
    for op in sorted(unknown_opcode_samples):
        print(f"\n  ── opcode 0x{op:04X} ──")
        for s in unknown_opcode_samples[op]:
            print(f"    src={s['src']} → dst={s['dst']}  frame={s['frame_len']}B")
            body = s['body']
            # Wrap hex at 60 chars per line for readability
            for i in range(0, len(body), 60):
                print(f"      {body[i:i+60]}")

    report_decode()


def report_decode():
    if not DECODE:
        return
    if p2_body is None:
        print("\n[!] --decode needs p2_asdu.py and p2_body.py beside this script")
        return
    total = sum(decode_stats.values())
    print(f"\n=== body decode against the declared structures ({total} request bodies) ===")
    for k, v in decode_stats.most_common():
        print(f"  {v:7d}  {k}")
    if decode_errors:
        print("\n  where it stopped early:")
        for k, v in decode_errors.most_common(12):
            print(f"  {v:7d}  {k}")
    for opcode, r in decode_dump:
        print(f"\n  ── 0x{opcode:04X} {r.struct} — {r.consumed}/{r.length} bytes"
              f"{'' if r.error is None else '  (' + r.error + ')'}")
        for f in r.fields:
            v = f.value if not isinstance(f.value, (bytes, bytearray)) else f.value.hex()
            print(f"      +{f.offset:<5d} {f.width:<4d} {f.type:<20.20} {f.path:<44.44} {v!r}")


if __name__ == "__main__":
    main()
