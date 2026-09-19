"""Reassembly and tallying in `analyze_pcap.py`, the last public tool without tests.

The tool's whole output is counts, so a defect in it does not crash — it prints
a smaller number. Both defects pinned here were of exactly that shape.

Everything below drives `consume_segment` directly with bytes, so none of it
needs tshark or a capture. The frames are synthetic, in the structure real ones
have, with invented node names.
"""
from __future__ import annotations

import struct

import pytest

import analyze_pcap as ap

SLOTS = ("SITEBLN", "SUPERVISOR", "SITEBLN", "NODE1")
OP_DBCHANGE_POINT = 0x0951
OP_EBLN_PING = 0x4640


def frame(opcode=OP_EBLN_PING, slots=SLOTS, body=b"", seq=1, direction=0x00):
    """A complete P2 frame with a DERIVED msg_type (PROTOCOL.md 6.2)."""
    payload = bytes([direction]) + b"".join(s.encode() + b"\x00" for s in slots)
    if direction == 0x00:
        payload += struct.pack(">H", opcode)
    payload += body
    msg_type = 13 + sum(len(s) + 1 for s in slots)
    return struct.pack(">III", 12 + len(payload), msg_type, seq) + payload


def error_frame(code, slots=SLOTS, seq=1):
    payload = b"\x05" + b"".join(s.encode() + b"\x00" for s in slots) \
        + struct.pack(">H", code)
    return struct.pack(">III", 12 + len(payload),
                       13 + sum(len(s) + 1 for s in slots), seq) + payload


@pytest.fixture(autouse=True)
def clean_state():
    """The tool keeps its tallies in module globals. Reset between cases."""
    for name in ("streams", "opcode_counts", "opcode_by_dir", "error_codes",
                 "msg_types", "next_seq", "unknown_opcode_samples",
                 "opcode_sizes", "opcode_by_port", "decode_stats",
                 "decode_errors"):
        getattr(ap, name).clear()
    ap.decode_dump.clear()
    for counter in (ap.retransmit_bytes, ap.gap_bytes, ap.desync_bytes,
                    ap.desync_events):
        counter[0] = 0
    yield


def feed(*segments, src="10.0.0.9", sport=40000, dst="10.0.0.1", dport=5033,
         stream="1", start=1):
    seq = start
    for s in segments:
        ap.consume_segment(s, src, sport, dst, dport, seq, stream)
        seq += len(s)
    return seq


# ───────────────────────────────────────────────────────── routing

def test_routing_offset_is_one_plus_the_slot_bytes():
    """The direction byte is followed immediately by slot 0 -- no extra NUL."""
    payload = frame()[12:]
    assert ap.parse_routing(payload) == 1 + sum(len(s) + 1 for s in SLOTS)


def test_routing_refuses_a_payload_it_cannot_walk():
    assert ap.parse_routing(b"") is None
    assert ap.parse_routing(b"\x00SITEBLN") is None          # no terminator
    assert ap.parse_routing(b"\x00A\x00B\x00") is None       # only two slots


# ───────────────────────────────────────────────────────── tallying

def test_a_request_is_counted_with_its_opcode_and_size():
    f = frame(OP_EBLN_PING)
    feed(f)
    assert ap.opcode_counts[OP_EBLN_PING] == 1
    assert ap.opcode_sizes[OP_EBLN_PING] == [len(f)]
    assert ap.opcode_by_port[5033][OP_EBLN_PING] == 1
    assert sum(ap.msg_types.values()) == 1


def test_a_zero_length_body_request_is_counted():
    """The DBCHANGE notifications: opcode, and nothing after it.

    `body` is exactly two bytes here, which is the boundary the tool's own
    length guard sits on.
    """
    feed(frame(OP_DBCHANGE_POINT))
    assert ap.opcode_counts[OP_DBCHANGE_POINT] == 1


def test_an_error_frame_is_counted_as_an_error_not_an_opcode():
    feed(error_frame(0x0003))
    assert ap.error_codes[0x0003] == 1
    assert sum(ap.opcode_counts.values()) == 0


def test_a_success_response_counts_its_header_but_no_opcode():
    """A reply carries no opcode field, so reading one would read body bytes."""
    feed(frame(direction=0x01, body=b"\x02\x40\x00\x00"))
    assert sum(ap.opcode_counts.values()) == 0
    assert sum(ap.msg_types.values()) == 1


# ───────────────────────────────────────────────────────── reassembly

def test_a_frame_split_across_segments_is_reassembled():
    f = frame()
    feed(f[:10], f[10:25], f[25:])
    assert ap.opcode_counts[OP_EBLN_PING] == 1


def test_several_frames_in_one_segment_are_all_pulled():
    feed(frame() + frame() + frame(OP_DBCHANGE_POINT))
    assert ap.opcode_counts[OP_EBLN_PING] == 2
    assert ap.opcode_counts[OP_DBCHANGE_POINT] == 1


def test_a_retransmission_is_counted_once():
    """Appending in arrival order would parse the same bytes twice."""
    f = frame()
    ap.consume_segment(f, "10.0.0.9", 40000, "10.0.0.1", 5033, 1, "1")
    ap.consume_segment(f, "10.0.0.9", 40000, "10.0.0.1", 5033, 1, "1")
    assert ap.opcode_counts[OP_EBLN_PING] == 1
    assert ap.retransmit_bytes[0] == len(f)


def test_a_partial_overlap_keeps_only_the_new_tail():
    f = frame() + frame(OP_DBCHANGE_POINT)
    ap.consume_segment(f[:40], "10.0.0.9", 40000, "10.0.0.1", 5033, 1, "1")
    # resent from byte 20, carrying 20 bytes already held plus the rest
    ap.consume_segment(f[20:], "10.0.0.9", 40000, "10.0.0.1", 5033, 21, "1")
    assert ap.retransmit_bytes[0] == 20
    assert ap.opcode_counts[OP_EBLN_PING] == 1
    assert ap.opcode_counts[OP_DBCHANGE_POINT] == 1


def test_a_gap_is_counted_and_does_not_misalign_what_follows():
    """Bytes never captured. Carrying the stale prefix would shift everything."""
    f = frame()
    ap.consume_segment(f[:10], "10.0.0.9", 40000, "10.0.0.1", 5033, 1, "1")
    # ten bytes placed from offset 1, so the next expected offset is 11
    ap.consume_segment(f, "10.0.0.9", 40000, "10.0.0.1", 5033, 500, "1")
    assert ap.gap_bytes[0] == 500 - 11
    assert ap.opcode_counts[OP_EBLN_PING] == 1      # the whole frame, not two


# ───────────────────────────────────────────────────────── desync

def test_an_impossible_length_prefix_is_discarded_and_COUNTED():
    """Dropping the buffer is right. Dropping it without saying so was not.

    The tool's whole output is counts, and it already reports trimmed
    duplicates and missing bytes. A third hole that reported nothing is the
    one a reader cannot account for.
    """
    junk = b"\xff\xff\xff\xff" + b"A" * 20
    feed(junk)
    assert ap.desync_events[0] == 1
    assert ap.desync_bytes[0] == len(junk)
    assert sum(ap.msg_types.values()) == 0


def test_a_length_below_the_format_floor_is_not_a_frame():
    """13 header bytes plus four NUL terminators is 17 (PROTOCOL.md 6.1.1).

    A prefix of 12 used to pass the guard and hand `process_p2_frame` an empty
    payload, which counted a header length for a frame that cannot exist.
    """
    feed(struct.pack(">III", 12, 51, 1) + b"\x00" * 8)
    assert sum(ap.msg_types.values()) == 0
    assert ap.desync_events[0] == 1


def test_a_valid_frame_after_a_desync_still_parses():
    """The buffer is cleared, not the stream: the next segment resynchronises.

    Fed at the offset that continues the stream, so this exercises recovery
    rather than the gap path.
    """
    junk = b"\xff\xff\xff\xff" + b"A" * 20
    feed(junk)
    feed(frame(), start=1 + len(junk))
    assert ap.opcode_counts[OP_EBLN_PING] == 1
    assert ap.gap_bytes[0] == 0


# ───────────────────────────────────────────────────────── port reuse

def test_one_four_tuple_can_carry_two_connections():
    """The regression test.

    A peer that closes and reconnects from the same ephemeral port is what
    tshark labels "[TCP Port numbers reused]". With relative sequence numbers
    the second connection restarts near zero while the reader holds a write
    cursor far past it -- so before `tcp.stream` joined the key, every byte of
    it read as a retransmission and was thrown away without a word. On one
    capture in the corpus that is 806 of 3,211 four-tuples.
    """
    f = frame()
    for stream in ("7", "8"):
        feed(*[f] * 20, stream=stream)
    assert ap.opcode_counts[OP_EBLN_PING] == 40
    assert ap.retransmit_bytes[0] == 0


def test_the_two_directions_of_one_connection_stay_separate():
    """Same stream id, opposite four-tuples: two independent byte streams."""
    f = frame()
    feed(f[:10], stream="1")
    feed(f, src="10.0.0.1", sport=5033, dst="10.0.0.9", dport=40000, stream="1")
    assert ap.opcode_counts[OP_EBLN_PING] == 1
    assert ap.retransmit_bytes[0] == 0


# ───────────────────────────────────────────────────────── labelling

def test_a_catalogued_opcode_is_named_and_an_uncatalogued_one_is_not():
    assert ap.opcode_label(OP_EBLN_PING) == "AP2_EBLN_PING"
    assert ap.opcode_label(0xFFFE) is None


def test_a_wire_note_is_appended_to_the_catalog_name():
    """The notes are a gloss on the generated catalog, never a second source."""
    label = ap.opcode_label(0x5354)
    assert label is not None and label.endswith("]")
    assert ap.WIRE_NOTES[0x5354] in label
