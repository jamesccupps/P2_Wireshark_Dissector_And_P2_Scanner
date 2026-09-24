"""virtual_pxc.py — an in-process virtual Siemens APOGEE PXC (PME1252).

Reproduces the wire behaviour `PROTOCOL.md` documents, for the opcodes a
scanner or a bridge needs to exercise. Responses are checked against the
structure of real captured panel responses by `verify.py`; what it does and
does not model is in `README.md`, stated rather than implied.

  Handshake / identity
    0x4640  IdentifyBlock — session establish and keepalive
    0x010C  SystemInfo compact (returns PME1252 build tag)
    0x0100  SystemInfo legacy (also used as mid-session EPing response)

  Reads
    0x0271  ReadProperty (legacy)
    0x0220  ReadShort (modern variant — accepted on legacy panels too)
    0x0294  SYST property read by hierarchical path
    0x5003  ScheduleObjectInfo

  Writes
    0x0240  WriteWithQuality — digital writes succeed; analog setpoints
            return 0x0E15 forcing the 0x4222 retry path
    0x4222  BulkPropertyWrite — always succeeds

  Discovery
    0x0986  EnumerateFLN
    0x0050  StatusQuery (cold-discovery bootstrap)

  Device install / commit
    0x4225  install / prepare
    0x4224  commit / finalize  (triggers 0x0368 push + COV flood)

  Push channel (TCP/5034 outbound to supervisor)
    0x0274  COV notification — pushed after every successful write
    0x0368  panel state notification — pushed after device-install commit

  Errors
    0x0003  not_found
    0x0E12  invalid_point_number
    0x0E15  physical_point_not_commandable (analog SYST writes)

This is a TEST FIXTURE, not a real panel emulator. It does not:
  - Honor maintenance windows or per-panel session-budget limits
  - Persist state across restarts
  - Implement the full opcode table (PPCL editor, alarms, schedules
    beyond read, BACnet integration, etc.)
  - Validate trailer timestamps or sequence-window math beyond what's
    needed for the scanner / bridge to talk to it

All fixture data uses generic placeholders (BUILDING1, NODE1, VAV001, ...).
No real-site identifiers appear in the test fixture file or this module.
"""
from __future__ import annotations

import json
import logging
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Wire constants. Deliberately independent of p2_scanner: a virtual panel
# that imports the client it is used to test cannot disagree with it, and
# disagreeing is the whole point.
# ─────────────────────────────────────────────────────────────────────────────

#: Bytes of frame header ahead of the routing slots:
#: 4 (total_len) + 4 (msg_type) + 4 (sequence) + 1 (direction).
HDR_BEFORE_SLOTS = 13

# `msg_type` is NOT a message class and NOT a "dialect" selector. It is the
# offset at which the routing-slot block ends -- a length, computed from the
# node names in the frame (PROTOCOL.md 6.2). The two values an earlier edition
# of this file named TYPE_DATA and TYPE_HEARTBEAT are simply the two lengths
# one particular site's names produced:
#
#     0x33 = 51 = 13 + 38 slot bytes
#     0x34 = 52 = 13 + 39 slot bytes
#
# They are kept only so older callers still import; nothing here compares
# against them.
TYPE_DATA      = 0x33   # deprecated: a length that one site happened to emit
TYPE_HEARTBEAT = 0x34   # deprecated: likewise


def expected_msg_type(slots) -> int:
    """`13 + the total bytes of the four NUL-terminated routing slots`."""
    return HDR_BEFORE_SLOTS + sum(len(sl) + 1 for sl in slots)


DIR_REQUEST = 0x00
DIR_SUCCESS = 0x01
DIR_ERROR   = 0x05

# Opcodes this panel answers
OP_STATUS_QUERY        = 0x0050
OP_SYSTEM_INFO_LEGACY  = 0x0100
OP_SYSTEM_INFO_COMPACT = 0x010C
OP_READ_LEGACY         = 0x0271
OP_READ_SHORT          = 0x0220
OP_WRITE_QUALITY       = 0x0240
OP_PROPERTY_READ_PATH  = 0x0294
OP_VALUE_PUSH          = 0x0274
OP_SERVICES_RENDERED   = 0x010D
OP_PANEL_STATE         = 0x0368
OP_ENUM_POINTS         = 0x0981
OP_ENUMERATE_FLN       = 0x0986
OP_IDENTIFY_BLOCK      = 0x4640
OP_BULK_WRITE          = 0x4222
OP_DEVICE_COMMIT       = 0x4224
OP_DEVICE_INSTALL      = 0x4225
OP_SCHEDULE_OBJECT     = 0x5003

# Unsolicited AP2_DBCHANGE_* notifications: a peer announcing a database
# change, sent on the session already open rather than by connecting back.
# The five observed on the wire, not the whole documented family.
OP_DBCHANGE_POINT      = 0x0951
OP_DBCHANGE_TREND      = 0x0954
OP_DBCHANGE_PPCL       = 0x0955
OP_DBCHANGE_CONTROLLER = 0x0956
OP_DBCHANGE_EQS_SCHED  = 0x0959
DBCHANGE_NOTIFY_OPCODES = frozenset({
    OP_DBCHANGE_POINT, OP_DBCHANGE_TREND, OP_DBCHANGE_PPCL,
    OP_DBCHANGE_CONTROLLER, OP_DBCHANGE_EQS_SCHED,
})

# Errors
ERR_NOT_FOUND                   = 0x0003
ERR_INVALID_POINT_NUMBER        = 0x0E12
ERR_PHYSICAL_NOT_COMMANDABLE    = 0x0E15

# Which point names succeed directly on 0x0240. Anything else
# whose 'kind' is analog_rw goes through the 0x4222 retry path. Names match
# the canonical fixture values; this list is the spec rule for digital
# state commands.
DIGITAL_WRITE_POINTS = frozenset({
    "HEAT.COOL", "DAY.NGT", "STPT DIAL", "FAN",
})


# ─────────────────────────────────────────────────────────────────────────────
# Frame primitives
# ─────────────────────────────────────────────────────────────────────────────


def _build_routing(bln: str, dest: str, scanner: str) -> bytes:
    """The four NUL-terminated routing slots.

    For supervisor -> panel: [BLN, dest_node, BLN, scanner_name]
    For panel -> supervisor: [BLN, scanner_name, BLN, panel_node]  (role swap)

    **No leading NUL.** PROTOCOL.md 6.1 gives the frame as
    `... u32 sequence | u8 direction | four NUL-terminated slots | ...`: the
    direction byte is immediately followed by the first slot. An earlier
    edition emitted an extra NUL here and skipped offset 1 when parsing, which
    cancelled against itself but ate the first character of slot 0 from any
    real client -- `MYBLN` parsed as `YBLN`.
    """
    return (bln.encode('ascii') + b'\x00'
            + dest.encode('ascii') + b'\x00'
            + bln.encode('ascii') + b'\x00'
            + scanner.encode('ascii') + b'\x00')


# The capability document a panel returns for 0x010D.  Element set and order
# follow the 55 real documents recovered from stored panel databases; see
# PROTOCOL.md 16.4.1.  LAN 0 is the TX-I/O island bus and the P1 trunks are
# LANs 1-3 (4.4) -- a client that assumes zero-based trunk numbering is off by
# one on every FLN address, which is exactly the kind of defect this fixture
# exists to surface.
_SERVICES_RENDERED_TEMPLATE = """<?xml version="1.0" encoding="ASCII" standalone="yes"?>
<ServicesRendered>
<Panel Name="%s">
<PanelBasics>
<ID_STRING>%s</ID_STRING>
<RevString>%s</RevString>
<LinkDate>%s</LinkDate>
<HardwareType>%s</HardwareType>
<BuildNumber>%s</BuildNumber>
<Platform>%s</Platform>
<VersionNumber>%s</VersionNumber>
</PanelBasics>
<Services>
<OperatorActivityLogging Enabled="NO" />
<AlarmBuffer Enabled="NO" />
<FLNTopology />
<LicenseManager />
<RENO Enabled="NO" />
<TXIO />
<TrendDST />
<WirelessFLN Enabled="NO" />
<Adapt />
<FLN LAN="0">ISLANDBUS</FLN>
<FLN LAN="1">P1</FLN>
<FLN LAN="2">P1</FLN>
<FLN LAN="3">P1</FLN>
<usbModem />
<usbPrinter />
<usbTool />
</Services>
</Panel>
</ServicesRendered>
"""


def _tlv(value: bytes | str) -> bytes:
    """`01 [u16 BE length] [value]` per PROTOCOL.md §8.1."""
    if isinstance(value, str):
        value = value.encode('ascii')
    return b'\x01' + struct.pack('>H', len(value)) + value


def _parse_lp_strings(data: bytes, start: int = 0) -> List[Tuple[str, int]]:
    """Pull out all `01 [u16 BE len] [ascii]` TLVs from data[start:]. Returns
    list of (value, end_offset)."""
    out = []
    i = start
    while i + 3 <= len(data):
        if data[i] == 0x01:
            L = struct.unpack('>H', data[i + 1:i + 3])[0]
            if 0 < L < 256 and i + 3 + L <= len(data):
                try:
                    v = data[i + 3:i + 3 + L].decode('ascii')
                    if v.isprintable() or v == '':
                        out.append((v, i + 3 + L))
                        i += 3 + L
                        continue
                except UnicodeDecodeError:
                    pass
        i += 1
    return out


def _frame(msg_type: int, seq: int, body: bytes) -> bytes:
    """Wrap a body in the 12-byte P2 header."""
    total_len = 12 + len(body)
    return struct.pack('>III', total_len, msg_type, seq) + body


# ─────────────────────────────────────────────────────────────────────────────
# The virtual panel
# ─────────────────────────────────────────────────────────────────────────────


class VirtualPxc:
    """Single-process, threaded virtual panel of a PME1252 PXC.

    Usage:
        panel = VirtualPxc.from_fixtures('fixtures.json')
        panel.start()          # binds to 127.0.0.1:<auto-port>
        print(panel.port)      # connect a client here
        ...
        panel.stop()
    """

    def __init__(
        self,
        bln: str = "MYBLN",
        site: str = "BUILDING1",
        node: str = "NODE1",
        firmware_build: str = "PME1252",
        hardware_platform: str = "PXME V2.8.10 APOGEE",
        build_date: str = "Oct 28 2013 12:31:01",
        # identity fields carried only by the 0x010D capability document.
        # Defaults are the most common values across the real set:
        # HardwareType PXME (48 of 55), Platform PME (49 of 55).
        services_id_string: str = "000000P00000XXX00-X00.X",
        hardware_type: str = "PXME",
        build_number: str = "3150",
        version_number: str = "V2.8.10",
        host: str = "127.0.0.1",
        port: int = 0,
        cov_push_enabled: bool = True,
        strict_framing: bool = True,
        strict_opcodes: bool = True,
    ) -> None:
        self.bln = bln
        self.site = site
        self.node = node
        self.firmware_build = firmware_build
        self.hardware_platform = hardware_platform
        self.build_date = build_date
        self.services_id_string = services_id_string
        self.hardware_type = hardware_type
        self.build_number = build_number
        self.version_number = version_number
        self.host = host
        self._requested_port = port
        self.port: int = 0  # filled in by start()
        self.cov_push_enabled = cov_push_enabled

        #: Drop frames whose `msg_type` disagrees with their routing slots,
        #: the way a panel does. Set False only to reproduce the behaviour of
        #: a virtual panel that cannot catch a hard-coded header length.
        self.strict_framing = strict_framing
        #: Answer an unknown opcode with `not_found` rather than a synthetic
        #: success. The permissive version let a client send anything and be
        #: told it worked.
        self.strict_opcodes = strict_opcodes

        #: Live client sockets, so a test can cut them. A panel reboots, hits
        #: its session budget, or sits behind a network that blips; a virtual panel that
        #: only ever holds the connection open tests none of a client's
        #: reconnect logic.
        self._live_conns = set()
        #: Accept and immediately close this many more connections.
        self._refuse_remaining = 0

        #: Counters a test can assert against.
        self.accepted_connections = 0
        self.refused_connections = 0
        self.dropped_bad_msg_type = 0
        self.unknown_opcodes: Dict[int, int] = {}

        self.devices: Dict[str, Dict[str, Any]] = {}
        #: Panel-internal points -- PPCL variables, virtual points, global
        #: analogs. Reachable ONLY through 0x0981, never through 0x0986.
        self.panel_points: Dict[str, Dict[str, Any]] = {}
        self.syst_objects: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        self._server_sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._client_threads: List[threading.Thread] = []

        # COV push state — the virtual panel keeps a list of (supervisor_ip, port) it
        # should push notifications to. Real PXCs connect outbound at boot;
        # the virtual panel connects on-demand for the supervisor that's currently
        # talking to it.
        self._cov_targets: set[Tuple[str, int]] = set()
        self._push_seq = 0x00400000  # arbitrary starting point for 5034 channel

    # ── Construction helpers ────────────────────────────────────────────────

    @classmethod
    def from_fixtures(cls, fixtures_path: Path | str, **overrides: Any) -> "VirtualPxc":
        """Build a VirtualPxc from a JSON fixtures file."""
        with open(fixtures_path, 'r', encoding='utf-8') as f:
            spec = json.load(f)
        panel = spec.get("panel", {})
        kw = {
            "bln": panel.get("bln", "MYBLN"),
            "site": panel.get("site", "BUILDING1"),
            "node": panel.get("name", "NODE1"),
            "firmware_build": panel.get("firmware_build", "PME1252"),
            "hardware_platform": panel.get("hardware_platform", "PXME V2.8.10 APOGEE"),
            "build_date": panel.get("build_date", "Oct 28 2013 12:31:01"),
        }
        kw.update(overrides)
        m = cls(**kw)
        for dev in spec.get("devices", []):
            m.devices[dev["name"]] = {
                "description": dev.get("description", ""),
                "application": dev.get("application", 0),
                "points": {n: dict(p) for n, p in dev.get("points", {}).items()},
                "installed": True,  # pre-installed by default
            }
        m.panel_points = {k: dict(v) for k, v in spec.get("panel_points", {}).items()
                          if not k.startswith("_")}
        m.syst_objects = {k: v for k, v in spec.get("_syst_objects", {}).items()
                          if not k.startswith("_")}
        return m

    # ── Server lifecycle ────────────────────────────────────────────────────

    def start(self) -> None:
        """Bind, listen, and start accepting clients in a background thread."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self._requested_port))
        self._server_sock.listen(8)
        self.port = self._server_sock.getsockname()[1]
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="virtual panel-pxc-accept", daemon=True)
        self._accept_thread.start()
        log.info("VirtualPxc listening on %s:%d (bln=%s node=%s build=%s)",
                 self.host, self.port, self.bln, self.node, self.firmware_build)

    def stop(self) -> None:
        """Signal shutdown and close the listener."""
        self._stop_event.set()
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None
        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        # Bind the listener to a local and never re-read the attribute. stop()
        # closes _server_sock AND sets it to None, so each re-read raced it:
        # settimeout() and accept() both sat outside any guard and could see a
        # closed fd (OSError 9) or None (AttributeError). Neither is caught by
        # the handlers below, so the thread died with an unhandled traceback on
        # most immediate start/stop cycles -- 173 of 200 measured. The suite
        # showed it only as PytestUnhandledThreadExceptionWarning, which is
        # easy to read as noise.
        #
        # The None check stays a plain `if` rather than an assert: asserts are
        # stripped under -O, and in a thread the resulting AttributeError would
        # be a silent hang.
        sock = self._server_sock
        if sock is None:
            return
        try:
            sock.settimeout(0.5)
        except OSError:
            return                      # stop() won the race; nothing to do
        while not self._stop_event.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(
                target=self._handle_client, args=(conn, addr),
                name=f"virtual-pxc-client-{addr[1]}", daemon=True)
            t.start()
            self._client_threads.append(t)

    # ── Fault injection ────────────────────────────────────────────────────

    def drop_connections(self) -> int:
        """Close every live client socket. Returns how many were cut."""
        with self._lock:
            conns = list(self._live_conns)
            self._live_conns.clear()
        for c in conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                c.close()
            except OSError:
                pass
        log.debug("VirtualPxc: dropped %d connection(s)", len(conns))
        return len(conns)

    def refuse_connections(self, n: int = 1) -> None:
        """Accept and immediately close the next `n` connections.

        Distinct from not listening at all: the TCP connect SUCCEEDS and the
        session then dies, which is what a panel that is up but not ready does,
        and what a client mistaking "connected" for "working" spins on.
        """
        with self._lock:
            self._refuse_remaining = max(0, int(n))

    # ── Unsolicited peer traffic ───────────────────────────────────────────

    def push_dbchange(self, opcode: int = OP_DBCHANGE_POINT) -> int:
        """Send an unsolicited `AP2_DBCHANGE_*` notification to every client.

        A peer announcing that its database changed -- a point added, a trend
        or PPCL program edited, a controller or EQS mode-schedule touched. It
        arrives **on the session already open**, unlike the COV push, which
        the panel delivers by connecting back on 5034.

        The shape is measured, not invented: direction byte, four routing
        slots, the two opcode bytes, and **nothing after**. 48 bytes at the
        site it was captured from, drawing a bare acknowledgement. It is not a
        two-byte payload -- no P2 frame that small exists (PROTOCOL.md 6.1.1),
        and an earlier reading of these as "bare-opcode keepalives" put a
        predicate into `p2_scanner` that could never once be true.

        Returns the number of clients it reached. Exists so a client's
        handling of peer-initiated traffic arriving mid-read can be exercised
        at all, which was ABSENT before.
        """
        if opcode not in DBCHANGE_NOTIFY_OPCODES:
            raise ValueError(
                "%#06x is not one of the DBCHANGE notifications observed on "
                "the wire %r -- a fixture that emits an unattested frame "
                "teaches the wrong wire format"
                % (opcode, sorted(DBCHANGE_NOTIFY_OPCODES)))
        frame = self._build_push_frame(struct.pack('>H', opcode))
        with self._lock:
            conns = list(self._live_conns)
        sent = 0
        for c in conns:
            try:
                c.sendall(frame)
                sent += 1
            except OSError as e:
                log.debug("VirtualPxc: DBCHANGE push failed: %s", e)
        return sent

    # ── Client connection handler ──────────────────────────────────────────

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        """Per-connection handler: read frames, dispatch, write responses."""
        with self._lock:
            self.accepted_connections += 1
            if self._refuse_remaining > 0:
                self._refuse_remaining -= 1
                self.refused_connections += 1
                refuse = True
            else:
                refuse = False
                self._live_conns.add(conn)
        if refuse:
            try:
                conn.close()
            except OSError:
                pass
            return

        conn.settimeout(30.0)
        buf = b""
        try:
            while not self._stop_event.is_set():
                # Pull more bytes
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                # Process all complete frames in buf
                while len(buf) >= 12:
                    total_len = struct.unpack('>I', buf[:4])[0]
                    if total_len < 12 or total_len > 65536:
                        # Malformed framing — abandon connection
                        log.warning("VirtualPxc: malformed frame from %s, closing", addr)
                        return
                    if len(buf) < total_len:
                        break  # wait for more data
                    frame = buf[:total_len]
                    buf = buf[total_len:]
                    response = self._dispatch_frame(frame, addr)
                    if response:
                        try:
                            conn.sendall(response)
                        except OSError:
                            return
        finally:
            with self._lock:
                self._live_conns.discard(conn)
            try:
                conn.close()
            except Exception:
                pass

    # ── Dispatch ───────────────────────────────────────────────────────────

    def _dispatch_frame(self, frame: bytes, addr: Tuple[str, int]) -> bytes:
        """Parse a complete P2 frame and produce a response (or empty bytes)."""
        if len(frame) < 13:
            return b""
        total_len, msg_type, seq = struct.unpack('>III', frame[:12])
        payload = frame[12:total_len]
        if not payload:
            return b""
        direction = payload[0]
        if direction not in (DIR_REQUEST, DIR_SUCCESS, DIR_ERROR):
            return b""

        # Parse the 4-slot routing header
        slots_with_offset = self._parse_routing_robust(payload)
        if slots_with_offset is None:
            return b""
        slots, body_offset = slots_with_offset
        if len(slots) < 4:
            return b""
        bln_in, dest_in, _bln2, scanner_in = slots

        # `msg_type` is a header length. A real panel mostly discards a frame
        # whose value disagrees with its own slots, and says nothing about it --
        # so a client that hard-codes the field goes unanswered, intermittently,
        # with nothing in a log. Reproduce that: it is the failure mode most
        # worth being able to test against.
        want = expected_msg_type(slots)
        if self.strict_framing and msg_type != want:
            with self._lock:
                self.dropped_bad_msg_type += 1
            log.debug("VirtualPxc: dropping frame, msg_type=%d but slots give %d",
                      msg_type, want)
            return b""

        body = payload[body_offset:]
        if len(body) < 2:
            return b""
        opcode = struct.unpack('>H', body[:2])[0]
        body_after_opcode = body[2:]

        # Remember the supervisor so we can push COVs to its 5034 listener.
        # The supervisor's IP is the peer addr we're talking to; the COV
        # port is conventionally 5034 (PROTOCOL.md §2.1).
        with self._lock:
            self._cov_targets.add((addr[0], 5034))

        # Dispatch
        handler = {
            OP_IDENTIFY_BLOCK:      self._handle_handshake,
            OP_SYSTEM_INFO_COMPACT: self._handle_sysinfo_compact,
            OP_SYSTEM_INFO_LEGACY:  self._handle_sysinfo_legacy,
            OP_SERVICES_RENDERED:   self._handle_services_rendered,
            OP_STATUS_QUERY:        self._handle_status_query,
            OP_READ_LEGACY:         self._handle_read,
            OP_READ_SHORT:          self._handle_read,
            OP_WRITE_QUALITY:       self._handle_write_0x0240,
            OP_BULK_WRITE:          self._handle_write_0x4222,
            OP_DEVICE_INSTALL:      self._handle_device_install,
            OP_DEVICE_COMMIT:       self._handle_device_commit,
            OP_PROPERTY_READ_PATH:  self._handle_property_read_0x0294,
            OP_SCHEDULE_OBJECT:     self._handle_schedule_object_info,
            OP_ENUMERATE_FLN:       self._handle_enumerate_fln,
            OP_ENUM_POINTS:         self._handle_enum_points,
        }.get(opcode)

        if handler is None:
            with self._lock:
                self.unknown_opcodes[opcode] = self.unknown_opcodes.get(opcode, 0) + 1
            log.debug("VirtualPxc: unhandled opcode 0x%04X (frame %d bytes)",
                      opcode, len(frame))
            # An earlier edition answered anything with a synthetic SUCCESS so
            # clients would not time out. That is the worst possible default
            # for a test fixture: every unimplemented opcode looks implemented,
            # and a client asserting on "did it work" passes against nothing.
            # A panel answers an operation it does not have with `not_found`.
            if self.strict_opcodes:
                return self._build_error(msg_type, seq, scanner_in, ERR_NOT_FOUND)
            return self._build_response(msg_type, seq, scanner_in,
                                         body=b'\x00\x00', success=True)

        return handler(msg_type, seq, scanner_in, body_after_opcode)

    def _parse_routing_robust(self, payload: bytes) -> Optional[Tuple[List[str], int]]:
        """Read the four NUL-terminated routing slots after the direction
        byte. Returns (slots, body_offset_into_payload) or None.

        Layout per PROTOCOL.md §6.1: `<dir> BLN \\0 dest \\0 BLN \\0 scanner \\0`
        — four NULs framing four ascii strings, first slot at
        offset 1. An earlier edition of this docstring described a
        leading routing NUL the protocol does not have, three lines
        above the code that was corrected away from it."""
        if len(payload) < 6:
            return None
        # Direction byte is offset 0; the first slot begins at offset 1.
        # An earlier edition started at 2, expecting a leading routing NUL the
        # protocol does not have, and so lost slot 0's first character.
        i = 1
        slots: List[str] = []
        start = i
        nulls = 0
        # Scan forward; each null terminates a slot
        while i < len(payload) and nulls < 4:
            if payload[i] == 0:
                try:
                    slots.append(payload[start:i].decode('ascii'))
                except UnicodeDecodeError:
                    return None
                nulls += 1
                start = i + 1
            i += 1
        if nulls < 4:
            return None
        return slots, i

    # ── Response builders ──────────────────────────────────────────────────

    def _build_routing_response(self, scanner: str) -> bytes:
        """Role-swapped routing slots for a panel response.

        Layout [BLN, scanner, BLN, panel_node], no leading NUL -- see
        `_build_routing`."""
        return (self.bln.encode('ascii') + b'\x00'
                + scanner.encode('ascii') + b'\x00'
                + self.bln.encode('ascii') + b'\x00'
                + self.node.encode('ascii') + b'\x00')

    def _build_response(self, msg_type: int, seq: int, scanner: str,
                        body: bytes, success: bool = True) -> bytes:
        """Build a complete P2 response frame: header + direction byte +
        role-swapped routing + body.

        The `msg_type` argument is **ignored**. An earlier edition echoed the
        request's value back; the response's slots are role-swapped, so echoing
        is right only by the accident that the two orderings hold the same four
        strings. It is a length -- compute it from the slots actually emitted.
        """
        dir_byte = bytes([DIR_SUCCESS if success else DIR_ERROR])
        slots = [self.bln, scanner, self.bln, self.node]
        payload = dir_byte + self._build_routing_response(scanner) + body
        return _frame(expected_msg_type(slots), seq, payload)

    def _build_error(self, msg_type: int, seq: int, scanner: str,
                     err_code: int) -> bytes:
        """Build an error response per PROTOCOL.md §7.2.2: direction=0x05, body is
        the 2-byte BE error code."""
        return self._build_response(msg_type, seq, scanner,
                                     struct.pack('>H', err_code),
                                     success=False)

    # ── Handlers ───────────────────────────────────────────────────────────

    def _handle_handshake(self, msg_type: int, seq: int,
                          scanner: str, body: bytes) -> bytes:
        """0x4640 IdentifyBlock — return SUCCESS with our identity echoed."""
        # `msg_type` is a header length and is computed by _build_response
        # (PME1252 actually responds with 0x0100 SystemInfo body but for
        # our purposes a clean handshake-ACK is sufficient; clients only
        # check direction=0x01 + non-zero response).
        resp_body = (_tlv(self.node)
                     + _tlv(self.site)
                     + _tlv(self.bln)
                     # 16-byte trailer, PROTOCOL.md §7.3.1
                     + b'\x00\x01\x01\x00\x00\x00\x00\x00\x00'
                     + struct.pack('>I', int(time.time()))
                     + b'\x00\x00\x00')
        return self._build_response(msg_type, seq, scanner, resp_body)

    #: Panel-configuration byte runs from a real 0x010C response -- memory
    #: sizes and revision codes. No names, addresses or point identifiers.
    _SYSINFO_CFG = bytes.fromhex(
        "001d0a060505050802000000ff0800040900000000000000000000000000000003000064")
    _SYSINFO_MID = bytes.fromhex("0a0000baffffff000a0000")
    _SYSINFO_TAIL = bytes.fromhex(
        "0400000000000000000000000000000000000813a900000000000000000000000000"
        "000004ea0506070000000000000000000000000000000000000000000000000000")
    _SYSINFO_END = bytes.fromhex("000600a0030b410a00210003000300")

    def _handle_sysinfo_compact(self, msg_type: int, seq: int,
                                 scanner: str, body: bytes) -> bytes:
        """0x010C SystemInfo compact, in the shape real panels emit.

        **No `00 00` header**: the body starts straight at the build-tag TLV.
        An earlier edition prefixed one out of habit and stopped after the three
        identity strings, which is the part `firmware_registry` reads -- so it
        worked, and looked nothing like a panel. 53 of the 60 real bodies in the
        cache share the structure below.
        """
        resp_body = (
            _tlv(self.firmware_build + ' ')   # trailing space mirrors real output
            + _tlv(self.hardware_platform)
            + _tlv(self.build_date)
            + self._SYSINFO_CFG
            + _tlv("V2.8 ") + _tlv("1.0") + _tlv("APOGEE")
            + b'\x00' + _tlv(b"")
            + self._SYSINFO_MID + _tlv(b"")
            + self._SYSINFO_TAIL + _tlv(b"")
            + b'\x02\x02' + _tlv(self.node)
            + self._SYSINFO_END)
        return self._build_response(msg_type, seq, scanner, resp_body)

    def _handle_sysinfo_legacy(self, msg_type: int, seq: int,
                                scanner: str, body: bytes) -> bytes:
        """0x0100 — legacy SystemInfo, used as mid-session EPing response."""
        return self._handle_sysinfo_compact(msg_type, seq, scanner, body)

    def _handle_services_rendered(self, msg_type: int, seq: int,
                                   scanner: str, body: bytes) -> bytes:
        """0x010D AP2_SERVICES_RENDERED — the panel's capability document.

        **The CONTENT is modelled on 55 real documents; the FRAMING is
        inferred.** Those 55 were recovered from stored panel databases, not
        from a capture: this exchange appears in none of the 229 captures in
        the corpus, so no example of how the response body is wrapped exists.
        The document is emitted here as a single string TLV (§8.1), which is
        how this panel emits every other string — a guess, and the most likely
        one, but a guess.

        A client MUST NOT treat this framing as specified. `verify.py` reports
        this row as PARTIAL for exactly that reason, and it stays PARTIAL until
        somebody captures a real `0x010D` exchange. What *is* faithful is the
        element vocabulary: `<Services>` carries eighteen distinct elements
        across the real set rather than the three the vendor template shows,
        `<PanelBasics>` carries `<Platform>` and `<VersionNumber>`, and the
        fieldbus layout appears as repeated `<FLN LAN="n">` elements in which
        **LAN 0 is the TX-I/O island bus and the P1 trunks are LANs 1-3**
        (PROTOCOL.md §4.4).
        """
        doc = _SERVICES_RENDERED_TEMPLATE % (
            self.node, self.services_id_string, self.firmware_build,
            self.build_date, self.hardware_type, self.build_number,
            self.hardware_platform, self.version_number)
        return self._build_response(msg_type, seq, scanner, _tlv(doc))

    def _handle_status_query(self, msg_type: int, seq: int,
                              scanner: str, body: bytes) -> bytes:
        """0x0050 — cold-discovery bootstrap. Return BLN + panel name
        in role-swapped routing, plus supervisor identity echo in body."""
        resp_body = (b'\x00\x50'                            # opcode echo
                     + b'\x01\x00\x04SYST'                   # scope TLV echo
                     + b'\x23\x3f\xff\xff\xff'               # SYST separator + wildcard
                     + _tlv(scanner if scanner else self._default_supervisor_name()))
        return self._build_response(msg_type, seq, scanner, resp_body)

    def _default_supervisor_name(self) -> str:
        return f"{self.site}DCC-SVR|5034"

    def _enum_catalog(self) -> List[Tuple[str, str, str, Optional[float], str]]:
        """Every point 0x0981 walks, sorted by the cursor key (device name).

        Two populations, and carrying both is the point of implementing this
        opcode at all:

          * FLN device points -- also reachable through 0x0986 + per-point reads
          * **panel-internal points** -- PPCL variables, virtual points, global
            analogs. These answer ONLY the bulk enumerate, which is why a bridge
            needs 0x0981 and why a virtual panel without it leaves that path untested.
        """
        rows: List[Tuple[str, str, str, Optional[float], str]] = []
        for dev_name in sorted(self.devices):
            dev = self.devices[dev_name]
            for pt_name in sorted(dev["points"]):
                pt = dev["points"][pt_name]
                rows.append((dev_name, pt_name, dev.get("description", ""),
                             pt.get("value"), pt.get("units", "")))
        for name in sorted(self.panel_points):
            pp = self.panel_points[name]
            rows.append((name, name, pp.get("description", ""),
                         pp.get("value"), pp.get("units", "")))
        rows.sort(key=lambda r: r[0])
        return rows

    def _handle_enum_points(self, msg_type: int, seq: int,
                            scanner: str, body: bytes) -> bytes:
        """0x0981 UPL_ALL_POINT -- one record per call, cursor-paginated."""
        # The cursor is the LAST non-empty TLV in the request; the two "*"
        # filters come first and an empty TLV trails it.
        tlvs = [v for v, _end in _parse_lp_strings(body)]
        cursor = ""
        for v in tlvs:
            if v and v != "*":
                cursor = v
        rows = self._enum_catalog()
        nxt = None
        for dev, pt, descr, value, units in rows:
            if dev > cursor:
                nxt = (dev, pt, descr, value, units)
                break
        if nxt is None:
            # End of walk. `not_found` is the enumeration terminator, and it is
            # what lets a client stop on an answer instead of on a timeout.
            return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)

        dev, pt, descr, value, units = nxt
        return self._build_response(msg_type, seq, scanner,
                                    self._enum_record_body(dev, descr, value, units))

    @staticmethod
    def _enum_record_body(name: str, descr: str,
                          value, units: str) -> bytes:
        """One 0x0981 record, in the shape real panels actually emit.

        Copied from the body cache rather than invented -- see this method's
        patch notes. The name appears THREE times, each followed by an empty
        TLV, which is what the scanner's compound-name detection reads.
        """
        analog = bool((units or "").strip())
        type_byte = 0x04 if analog else 0x02
        marker = 0x02 if analog else 0x06

        head = (b"\x00\x00"
                + _tlv(name) + _tlv(b"")
                + bytes([type_byte]) + b"\x00\x02\x00\x00"
                + _tlv(name) + _tlv(b"")
                + b"\x00\x01"
                + _tlv(name) + _tlv(b"")
                + _tlv(descr))

        if value is None:
            # Label-only entry: no sentinel, no float, no units.
            return head

        meta = (b"\x3f\xff\xff\xf7\x00\x00" + bytes([marker])
                + struct.pack(">f", float(value)))
        if analog:
            return (head + meta + b"\x00\x00\x00"
                    + _tlv(units)
                    + b"\x00\x3f\x80\x00\x00\x00\x02"
                    + _tlv(b"") + b"\x01" + _tlv(b"\x00"))
        # Digital: the units TLV is present but EMPTY -- omitting it would make
        # the record parse as label-only and lose the value.
        return (head + meta + b"\x00\x00\x00\xff\xfe"
                + _tlv(b"") + b"\x00")

    def _fln_record_body(self, dev_name: str) -> bytes:
        """One 0x0986 record, in the shape real panels emit.

        Like 0x0981, **the device name repeats three times** -- and the
        application number lives inside the first byte run (`09c4` = 2500 in the
        sample this is copied from), not in a TLV. An earlier edition emitted
        three name/description pairs and matched nothing.
        """
        dev = self.devices.get(dev_name, {})
        app = int(dev.get("application", 0))
        return (b"\x00\x00"
                + _tlv(dev_name)
                + b"\x00\x10" + struct.pack(">H", app) + b"\x00\x00\x00\x02\x00\x00"
                + _tlv(dev_name)
                + b"\x00\x01"
                + _tlv(dev_name)
                + _tlv(dev.get("description", "")[:6] or dev_name)
                + bytes.fromhex("0000000000011200000000020300010014000000000000"))

    @staticmethod
    def _bare_lp_strings(data: bytes):
        """Length-prefixed strings with no tag byte, as 0x0986 requests carry.

        Mirrors the scan `enumerate_fln_devices` uses on responses: a `u16` that
        is followed by exactly that many printable ASCII bytes.
        """
        out, i = [], 0
        while i < len(data) - 2:
            n = struct.unpack('>H', data[i:i + 2])[0]
            if 0 < n < 60 and i + 2 + n <= len(data):
                try:
                    v = data[i + 2:i + 2 + n].decode('ascii')
                except UnicodeDecodeError:
                    v = None
                if v is not None and v.isprintable():
                    out.append(v)
                    i += 2 + n
                    continue
            i += 1
        return out

    def _handle_enumerate_fln(self, msg_type: int, seq: int,
                               scanner: str, body: bytes) -> bytes:
        """0x0986 UPL_ALL_TEC -- one installed device per call, cursor-walked.

        An earlier edition returned every device in a single response, which no
        panel does and which left the scanner's cursor logic unexercised.
        """
        found = self._bare_lp_strings(body)
        cursor = ""
        for v in found:
            if v and v != "*":
                cursor = v

        with self._lock:
            installed = sorted(n for n, d in self.devices.items()
                               if d.get("installed", True))
        nxt = next((n for n in installed if n > cursor), None)
        if nxt is None:
            return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
        return self._build_response(msg_type, seq, scanner,
                                    self._fln_record_body(nxt))

    def _handle_read(self, msg_type: int, seq: int,
                      scanner: str, body: bytes) -> bytes:
        """0x0271 / 0x0220 — read a point. Body shape:
        00 00 [TLV device_name] [TLV point_name] ...
        Response carries the point value block, PROTOCOL.md §10.4."""
        strings = _parse_lp_strings(body)
        if len(strings) < 2:
            # Some reads carry scope first (e.g. 0x0220 NONE-scope read-back
            # has 01 00 04 SYST before the device/point TLVs)
            return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
        # Heuristic: skip "SYST" / "NONE" scope TLVs to find the device + point
        meaningful = [s for s, _ in strings if s not in ("SYST", "NONE")]
        if len(meaningful) < 2:
            return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
        device_name, point_name = meaningful[0], meaningful[1]

        with self._lock:
            dev = self.devices.get(device_name)
            if dev is None:
                return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
            point = dev["points"].get(point_name)
            if point is None:
                return self._build_error(msg_type, seq, scanner, ERR_INVALID_POINT_NUMBER)
            value = float(point.get("value", 0.0))
            units = point.get("units", "")
            comm_status = point.get("comm_status", 0)  # 0 = online, 1 = stale

        # Value block per PROTOCOL.md §10.4 / §10.3. Scanner parser at
        # `p2_scanner._parse_read_response` requires:
        #   bytes i+0..i+2 = 01 00 00  (marker)
        #   bytes i+3..i+6 = sentinel — MUST be `3F FF FF FF` OR `00 00 00 00`
        #   byte  i+7      = 0x00  (status-group leading byte)
        #   byte  i+8      = comm_status (0x00 online, non-zero stale)
        #   byte  i+9      = data-type / error code byte
        #   bytes i+10..i+13 = f32 BE value
        # Previous byte (i-1) must be printable ASCII so the marker doesn't
        # false-match against random metadata sequences.
        kind = point.get("kind", "analog_rw")
        data_type_byte = 0x03 if kind.startswith("analog") else 0x01

        body_out = (
            b'\x00\x00'                                  # response header
            + _tlv(device_name)                          # echo device
            + _tlv(point_name)                           # echo point
            # device description: structured as `00 01 01 00 LL [ascii]` so the
            # ASCII letter at the end ensures the value-block marker's previous
            # byte is printable ASCII (scanner predicate)
            + b'\x00\x01\x01\x00' + struct.pack('>B', len(dev.get("description", "")))
            + dev.get("description", "").encode('ascii')
            + _tlv(point_name)
            + b'\x01\x00\x00'                            # value-block marker (§10.4)
            + b'\x00\x00\x00\x00'                        # R2 sentinel (all-zero explicit-flags)
            + bytes([0x00, comm_status, data_type_byte]) # status group: lead(0) / comm / type
            + struct.pack('>f', value)                   # f32 BE value at marker+10
            + _tlv(units)
        )
        return self._build_response(msg_type, seq, scanner, body_out)

    def _handle_write_0x0240(self, msg_type: int, seq: int,
                              scanner: str, body: bytes) -> bytes:
        """0x0240 WriteWithQuality:
          - Digital writes (kind == digital_rw, name in DIGITAL_WRITE_POINTS)
            → SUCCESS directly
          - Analog setpoint writes → 0x0E15 (forces 0x4222 retry)
        """
        device, point, value = self._parse_write_body(body)
        if device is None:
            return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)

        with self._lock:
            dev = self.devices.get(device)
            if dev is None:
                return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
            pt = dev["points"].get(point)
            if pt is None:
                return self._build_error(msg_type, seq, scanner, ERR_INVALID_POINT_NUMBER)
            kind = pt.get("kind", "analog_rw")

        if kind == "digital_rw" or point in DIGITAL_WRITE_POINTS:
            # Direct success
            with self._lock:
                pt["value"] = float(value)
            self._schedule_cov_push(device, point, float(value))
            return self._write_success_response(msg_type, seq, scanner, device, point)
        else:
            # Force the retry
            return self._build_error(msg_type, seq, scanner, ERR_PHYSICAL_NOT_COMMANDABLE)

    def _handle_write_0x4222(self, msg_type: int, seq: int,
                              scanner: str, body: bytes) -> bytes:
        """0x4222 BulkPropertyWrite — always succeeds."""
        device, point, value = self._parse_write_body(body, has_extra_priority=True)
        if device is None:
            return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)

        with self._lock:
            dev = self.devices.get(device)
            if dev is None:
                return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
            pt = dev["points"].get(point)
            if pt is None:
                return self._build_error(msg_type, seq, scanner, ERR_INVALID_POINT_NUMBER)
            pt["value"] = float(value)

        self._schedule_cov_push(device, point, float(value))
        return self._write_success_response(msg_type, seq, scanner, device, point)

    def _parse_write_body(self, body: bytes, has_extra_priority: bool = False
                          ) -> Tuple[Optional[str], Optional[str], float]:
        """Common parser for 0x0240 / 0x4222 write bodies. Returns
        (device, point, value_f32) — all None on parse failure."""
        # Body shape: [01 00 04 SYST][23 separator][3F FF FF FF wildcard][00 00 reserved][...]
        # Skip scope + separator + sentinel + reserved (12 bytes) if present
        i = 0
        if body[i:i + 3] == b'\x01\x00\x04':
            i += 3 + 4   # 01 00 04 + "SYST"
            if i < len(body) and body[i] in (0x00, 0x23):
                i += 1   # separator
            if i + 4 <= len(body):
                i += 4   # wildcard
            i += 2       # reserved 00 00
        strings = _parse_lp_strings(body, i)
        if len(strings) < 2:
            return None, None, 0.0
        device = strings[0][0]
        point = strings[1][0]
        # Value sits at a deterministic offset after the second TLV; the
        # specific layout differs between 0x0240 and 0x4222.
        # Search the trailing bytes for an IEEE 754 f32 BE that decodes
        # to a sensible value.
        tail_start = strings[1][1]
        tail = body[tail_start:]
        value = 0.0
        # 0x4222 layout has 'ff ff 00 00 00' before the value; 0x0240 layout
        # has just '01 00 00 ...' markers. Easiest robust extraction: find
        # the LAST 4 bytes before any trailing 0x23 or end-of-body.
        # Strip the SYST trailer marker if present.
        if tail and tail[-1] == 0x23:
            tail = tail[:-1]
        # Walk backwards looking for a 4-byte f32 that decodes to a finite,
        # reasonable value.
        for k in range(len(tail) - 4, -1, -1):
            try:
                v = struct.unpack('>f', tail[k:k + 4])[0]
            except struct.error:
                continue
            if -1e9 < v < 1e9 and v == v:   # finite, not NaN
                if abs(v) > 1e-9 or k == len(tail) - 4:
                    value = v
                    break
        return device, point, value

    def _write_success_response(self, msg_type: int, seq: int, scanner: str,
                                 device: str, point: str) -> bytes:
        """Both 0x0240 success and 0x4222 success share the same response
        shape: 00 00 + device + point + 00 00."""
        body = b'\x00\x00' + _tlv(device) + _tlv(point) + b'\x00\x00'
        return self._build_response(msg_type, seq, scanner, body)

    def _handle_device_install(self, msg_type: int, seq: int,
                                scanner: str, body: bytes) -> bytes:
        """0x4225 device install. Returns SUCCESS — the simulated
        4-second latency is not reproduced here (tests would be too slow).
        Marks the device as 'installing'."""
        device = self._parse_device_only_body(body)
        if device is None:
            return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
        with self._lock:
            if device not in self.devices:
                return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
            self.devices[device]["_install_pending"] = True
        # SUCCESS response: echo device + 00 00 trailer
        body_out = b'\x00\x00' + _tlv(device) + b'\x00\x00'
        return self._build_response(msg_type, seq, scanner, body_out)

    def _handle_device_commit(self, msg_type: int, seq: int,
                               scanner: str, body: bytes) -> bytes:
        """0x4224 device commit. Returns SUCCESS, then asynchronously
        pushes 0x0368 panel-state + COV flood for every point on the device."""
        device = self._parse_device_only_body(body)
        if device is None:
            return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
        with self._lock:
            dev = self.devices.get(device)
            if dev is None:
                return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
            dev["installed"] = True
            dev["_install_pending"] = False
        # Schedule the side-effect pushes (panel state + COV flood)
        threading.Thread(
            target=self._post_commit_pushes, args=(device,),
            name=f"virtual panel-pxc-postcommit-{device}", daemon=True).start()
        body_out = b'\x00\x00' + _tlv(device) + b'\x00\x00'
        return self._build_response(msg_type, seq, scanner, body_out)

    def _parse_device_only_body(self, body: bytes) -> Optional[str]:
        """Extract the device name from 0x4224 / 0x4225 bodies (single TLV
        after the scope header)."""
        # Skip scope header (12 bytes): 01 00 04 SYST 23 3F FF FF FF 00 00
        i = 0
        if body[i:i + 3] == b'\x01\x00\x04':
            i += 12
        strings = _parse_lp_strings(body, i)
        return strings[0][0] if strings else None

    def _handle_property_read_0x0294(self, msg_type: int, seq: int,
                                      scanner: str, body: bytes) -> bytes:
        """0x0294 SYST property read by hierarchical path."""
        # Body: 01 00 04 SYST 00 3F FF FF FF 00 00 [TLV object_path] [TLV property_name] ...
        i = 0
        if body[i:i + 3] == b'\x01\x00\x04':
            i += 12
        strings = _parse_lp_strings(body, i)
        # Filter scope strings
        meaningful = [s for s, _ in strings if s not in ("SYST", "NONE")]
        if len(meaningful) < 2:
            return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
        obj_path, prop_name = meaningful[0], meaningful[1]

        with self._lock:
            obj = self.syst_objects.get(obj_path)
            if obj is None:
                return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
            prop = obj.get(prop_name)
            if prop is None or not isinstance(prop, dict):
                return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
            value = float(prop.get("value", 0.0))
            units = prop.get("units", "")

        body_out = (
            b'\x00\x00'
            + _tlv(obj_path)
            + _tlv(prop_name)
            + b'\x01\x00\x00'                         # value marker
            + b'\x00\x00\x00\x01'                     # R2 sentinel
            + b'\x00\x00\x06'                         # status group
            + struct.pack('>f', value)
            + _tlv(units)
        )
        return self._build_response(msg_type, seq, scanner, body_out)

    def _handle_schedule_object_info(self, msg_type: int, seq: int,
                                      scanner: str, body: bytes) -> bytes:
        """0x5003 ScheduleObjectInfo. Returns SUCCESS with object
        descriptor + current state. Single-TLV body (object_path)."""
        i = 0
        if body[i:i + 3] == b'\x01\x00\x04':
            i += 12
        strings = _parse_lp_strings(body, i)
        meaningful = [s for s, _ in strings if s not in ("SYST", "NONE")]
        if not meaningful:
            return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
        obj_path = meaningful[0]
        with self._lock:
            obj = self.syst_objects.get(obj_path)
            if obj is None:
                return self._build_error(msg_type, seq, scanner, ERR_NOT_FOUND)
            descr = obj.get("DESCR", "")
            current_state_dict = obj.get("CURRENT_STATE", {"value": 0.0})
            current_state = float(current_state_dict.get("value", 0.0))
        body_out = (
            b'\x00\x00'
            + _tlv(obj_path)
            + _tlv(descr if isinstance(descr, str) else "")
            + b'\x01\x00\x00\x00\x00\x00\x01\x00\x00\x06'
            + struct.pack('>f', current_state)
        )
        return self._build_response(msg_type, seq, scanner, body_out)

    # ── Push channel (panel → supervisor on TCP/5034) ──────────────────────

    def _schedule_cov_push(self, device: str, point: str, value: float) -> None:
        """Queue a COV push for delivery via the 5034 connect-back. Non-blocking."""
        if not self.cov_push_enabled:
            return
        threading.Thread(
            target=self._send_cov_push, args=(device, point, value),
            name="virtual-pxc-cov", daemon=True).start()

    def _send_cov_push(self, device: str, point: str, value: float) -> None:
        """Open a TCP connection to each known supervisor (host, 5034) and
        send a 0x0274 ValuePush frame. The PANEL makes the
        outbound connection; supervisor's only job is to ACK."""
        time.sleep(0.02)  # brief delay so the write SUCCESS lands first
        with self._lock:
            targets = list(self._cov_targets)
        body = (
            b'\x02\x74'                                  # opcode
            + b'\x00\x01\x00\x00'                        # header per pcap reference
            + _tlv(device)
            + _tlv(point)
            + struct.pack('>f', value)
            + b'\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00'  # type=analog + padding
        )
        for target in targets:
            self._push_to(target, body)

    def _post_commit_pushes(self, device: str) -> None:
        """After a 0x4224 device-commit: push 0x0368 panel state + COV flood
        for every point on the device."""
        time.sleep(0.05)
        # 0x0368 panel state notification with state_code=0x03
        state_body = (
            b'\x03\x68'
            + b'\x03'                                     # state code: device-config-change committed
            + b'\x01\x00\x00'
            + _tlv(self.node)
            + b'\x00\x01\x00\x11'
        )
        with self._lock:
            targets = list(self._cov_targets)
            dev = self.devices.get(device)
            if dev is None:
                return
            points = list(dev["points"].items())
        for target in targets:
            self._push_to(target, state_body)
        # Then the COV flood
        time.sleep(0.02)
        for point_name, pt in points:
            body = (
                b'\x02\x74'
                + b'\x00\x01\x00\x00'
                + _tlv(device)
                + _tlv(point_name)
                + struct.pack('>f', float(pt.get("value", 0.0)))
                + b'\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00'
            )
            for target in targets:
                self._push_to(target, body)
            time.sleep(0.005)

    def _push_to(self, target: Tuple[str, int], body: bytes) -> None:
        """Open a TCP connection to (supervisor_host, 5034) and send one
        framed push. The supervisor's ACK (if any) is ignored — the panel
        treats this channel as fire-and-forget."""
        host, port = target
        frame = self._build_push_frame(body)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((host, port))
            sock.sendall(frame)
            sock.close()
        except (OSError, socket.timeout) as e:
            log.debug("VirtualPxc: COV push to %s:%d failed: %s", host, port, e)

    def _build_push_frame(self, body: bytes) -> bytes:
        """A complete panel-originated frame: routing reversed, msg_type derived.

        Routing is panel -> supervisor, so the supervisor's identity is in slot
        1 and the panel's name in slot 3 -- the opposite of a
        supervisor-initiated frame. It goes through `_build_routing` like every
        other frame here. An earlier edition rolled its own inline, starting it
        with a NUL and then prepending the direction byte, so every push left
        with TWO direction bytes: a conforming client read slot 0 as empty,
        lost the node name, and took its first two characters for the opcode
        (`NODE1` -> `0x4E4F`).

        `msg_type` is DERIVED, never the module's TYPE_DATA constant. A panel
        that silently drops an inbound frame whose header length contradicts
        its own slots cannot be emitting one itself -- it was sending the
        constant 51 where those slots required 33.
        """
        with self._lock:
            self._push_seq = (self._push_seq + 1) & 0xFFFFFFFF
            push_seq = self._push_seq
        slots = (self.bln, self._default_supervisor_name(), self.bln, self.node)
        payload = (bytes([DIR_REQUEST])
                   + _build_routing(slots[0], slots[1], slots[3])
                   + body)
        return _frame(expected_msg_type(slots), push_seq, payload)
