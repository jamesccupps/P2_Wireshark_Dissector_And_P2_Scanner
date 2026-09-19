"""
poller.py — One polling worker per PXC node.

Each NodePoller:
  - Owns one persistent P2Connection to its PXC
  - Polls its assigned points serially with the configured inter-read delay
  - Reconnects with exponential backoff on connection loss
  - Pushes results into BACnet objects via the status module

Why one connection per PXC: PXCs have an 8-16 peer-session budget. Sharing
one connection across all reads on a panel is the well-behaved approach
the GUI's TaskRunner already established.

Why one thread per node: a slow or down PXC shouldn't block reads on
healthy panels. Independent threads also let us reconnect each panel
on its own backoff timer.
"""
from __future__ import annotations

import logging
import random
import threading
import time
from typing import Dict, List, Optional

from .config import BridgeConfig, SiteConfig
from .manifest import PointEntry
from .status import update_from_read, apply_update, ObjectUpdate, \
    RELIABILITY_COMM_FAILURE, STATUS_FLAGS_FAULT

log = logging.getLogger(__name__)


class NodePoller(threading.Thread):
    """Polls one PXC node. Started by Bridge; stops on stop_event."""

    def __init__(
        self,
        node_name: str,
        host: str,
        site: SiteConfig,
        cfg: BridgeConfig,
        points: List[PointEntry],
        objects: Dict[tuple, object],     # (object_type, instance) -> bacpypes3 obj
        stop_event: threading.Event,
        scanner_module,                   # the imported p2_scanner module
    ) -> None:
        super().__init__(name=f"poller-{node_name}", daemon=True)
        self.node_name = node_name
        self.host = host
        self.site = site
        self.cfg = cfg
        self.points = points
        self.objects = objects
        self.stop_event = stop_event
        self.p2 = scanner_module

        # Stats
        self.total_reads = 0
        self.successful_reads = 0
        self.failed_reads = 0
        self.last_cycle_duration_s: float = 0.0
        self.last_cycle_completed_at: Optional[float] = None
        self.last_connect_attempt_at: Optional[float] = None
        self.connection_state: str = "disconnected"

    # ─── connection management ──────────────────────────────────────────────

    def _open_connection(self):
        """Open a P2Connection. Returns the connection or None on failure."""
        self.last_connect_attempt_at = time.time()
        try:
            conn = self.p2.P2Connection(
                self.host,
                network=self.site.p2_network,
                scanner_name=self.site.scanner_name,
            )
        except Exception as e:
            log.error("[%s] P2Connection construction failed: %s",
                      self.node_name, e)
            return None

        if not conn.connect(self.node_name.lower()):
            log.warning("[%s] P2 handshake failed against %s",
                        self.node_name, self.host)
            try:
                conn.close()
            except Exception:
                pass
            return None

        log.info("[%s] Connected to %s — handshake OK", self.node_name, self.host)
        return conn

    def _mark_all_comm_failure(self):
        """When connection drops, flip every point on this node to faulted."""
        update = ObjectUpdate(
            present_value=None,
            reliability=RELIABILITY_COMM_FAILURE,
            status_flags=STATUS_FLAGS_FAULT,
        )
        for entry in self.points:
            obj = self.objects.get((entry.bacnet_object_type, entry.bacnet_instance))
            if obj is not None:
                apply_update(obj, update)

    # ─── main loop ──────────────────────────────────────────────────────────

    def run(self) -> None:
        log.info("[%s] Poller starting — %d points",
                 self.node_name, len(self.points))
        backoff = self.cfg.reconnect_backoff_initial_s

        while not self.stop_event.is_set():
            self.connection_state = "connecting"
            conn = self._open_connection()
            if conn is None:
                self._mark_all_comm_failure()
                self.connection_state = "disconnected"
                # Capped exponential backoff
                wait = min(backoff, self.cfg.reconnect_backoff_max_s)
                log.info("[%s] Reconnecting in %.0fs", self.node_name, wait)
                if self.stop_event.wait(wait):
                    break
                backoff = min(backoff * 2, self.cfg.reconnect_backoff_max_s)
                continue

            # Connected — reset backoff
            self.connection_state = "connected"
            backoff = self.cfg.reconnect_backoff_initial_s

            try:
                self._run_polling_loop(conn)
            except Exception as e:
                log.exception("[%s] Polling loop crashed: %s",
                              self.node_name, e)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
                self.connection_state = "disconnected"

        log.info("[%s] Poller stopped", self.node_name)

    def _run_polling_loop(self, conn) -> None:
        """
        Cycle through this node's points until told to stop or connection
        breaks.

        Two read paths run side by side on the same persistent connection:

          FLN device points (point_source="fln")
              Polled individually via read_point(device, point, node).
              Lowest-due-first scheduler — each point has its own
              poll_interval_s. Single-threaded, sub-second per read.

          Panel-internal points (point_source="panel")
              Read in bulk via enumerate_all_points() (opcode 0x0981).
              The Points section of a PXC is a separate namespace from FLN
              devices: virtual points, PPCL working variables, and panel
              I/O all live there and respond only to the bulk enumerate,
              not to per-point read_point(). One enumerate covers every
              panel point on the node in ~10–20s and returns value, units,
              and description for each.

        Cadence: panel enumerate runs every panel_enumerate_interval_s.
        Between enumerates, FLN reads continue normally.
        """
        enabled_points = [e for e in self.points if e.enabled]
        if not enabled_points:
            log.info("[%s] No enabled points to poll", self.node_name)
            self.stop_event.wait()
            return

        fln_points = [e for e in enabled_points
                      if getattr(e, "point_source", "fln") != "panel"]
        panel_points = [e for e in enabled_points
                        if getattr(e, "point_source", "fln") == "panel"]
        # Fast lookup by point name for matching enumerate response entries
        # back to manifest entries.
        panel_lookup: Dict[str, PointEntry] = {e.name: e for e in panel_points}

        log.info("[%s] Polling %d FLN points + %d panel points",
                 self.node_name, len(fln_points), len(panel_points))

        # Run an immediate panel enumerate so panel objects populate fast
        last_panel_enum_at: float = 0.0
        if panel_points:
            self._run_panel_enumerate(conn, panel_lookup)
            last_panel_enum_at = time.monotonic()

        # FLN scheduler — stagger initial reads across the configured jitter
        now = time.monotonic()
        next_due: Dict[tuple, float] = {
            e.key: now + random.uniform(0, self.cfg.poll_jitter_s)
            for e in fln_points
        }

        cycle_started_at = now
        cycle_reads_this_pass: set = set()

        while not self.stop_event.is_set():
            now = time.monotonic()

            # Time for a panel enumerate?
            if panel_points and (
                now - last_panel_enum_at >= self.cfg.panel_enumerate_interval_s
            ):
                try:
                    self._run_panel_enumerate(conn, panel_lookup)
                except (BrokenPipeError, ConnectionResetError, OSError) as e:
                    log.warning("[%s] Connection error during panel enumerate: %s",
                                self.node_name, e)
                    return  # let run() reconnect
                last_panel_enum_at = time.monotonic()
                continue

            if not fln_points:
                # Panel-only node — sleep until next enumerate is due
                wait = max(
                    0.5,
                    self.cfg.panel_enumerate_interval_s
                    - (time.monotonic() - last_panel_enum_at),
                )
                if self.stop_event.wait(min(wait, 5.0)):
                    return
                continue

            # FLN scheduler: find any due points
            due_now: List[tuple] = []
            soonest_pending: Optional[float] = None
            for entry in fln_points:
                t = next_due[entry.key]
                if t <= now:
                    due_now.append((t, entry))
                elif soonest_pending is None or t < soonest_pending:
                    soonest_pending = t

            if not due_now:
                # Sleep until next pending — but cap so we revisit the
                # panel enumerate timer too.
                if soonest_pending is None:
                    wait = 1.0
                else:
                    wait = min(max(0.05, soonest_pending - now), 1.0)
                if panel_points:
                    panel_due_in = (
                        self.cfg.panel_enumerate_interval_s
                        - (now - last_panel_enum_at)
                    )
                    if panel_due_in > 0:
                        wait = min(wait, panel_due_in)
                if self.stop_event.wait(max(0.05, wait)):
                    return
                continue

            # Read the most-overdue FLN point first
            due_now.sort(key=lambda x: x[0])
            _, entry = due_now[0]
            cycle_reads_this_pass.add(entry.key)

            self.total_reads += 1
            try:
                result = conn.read_point(entry.device, entry.name,
                                         self.node_name.lower())
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                log.warning("[%s] Connection error during read of %s/%s: %s",
                            self.node_name, entry.device, entry.name, e)
                return

            if result is not None and result.get("value") is not None:
                self.successful_reads += 1
            else:
                self.failed_reads += 1

            update = update_from_read(entry, result)
            obj = self.objects.get(
                (entry.bacnet_object_type, entry.bacnet_instance))
            if obj is not None:
                apply_update(obj, update)

            # Schedule next read for this point
            next_due[entry.key] = time.monotonic() + entry.poll_interval_s

            # Cycle bookkeeping — log when every enabled FLN point covered
            if len(cycle_reads_this_pass) >= len(fln_points):
                duration = time.monotonic() - cycle_started_at
                self.last_cycle_duration_s = duration
                self.last_cycle_completed_at = time.time()
                log.info("[%s] FLN cycle complete: %d points in %.1fs "
                         "(success=%d fail=%d total=%d)",
                         self.node_name, len(fln_points), duration,
                         self.successful_reads, self.failed_reads,
                         self.total_reads)
                cycle_reads_this_pass.clear()
                cycle_started_at = time.monotonic()

            # Inter-read delay
            if self.cfg.inter_read_delay_s > 0:
                if self.stop_event.wait(self.cfg.inter_read_delay_s):
                    return

    def _run_panel_enumerate(self, conn,
                             panel_lookup: Dict[str, PointEntry]) -> None:
        """
        Run one panel-wide enumerate (opcode 0x0981) and update every
        matching panel-source manifest entry's BACnet object.

        Strategy:
          1. Call enumerate_all_points — returns list of dicts with
             {device, point, value, units, description, subkey}.
          2. For each entry whose `point` matches a manifest panel point
             on this node, push the value into the BACnet object.
          3. For panel points not present in this enumerate response,
             flag them with comm-fault — the panel forgot about them
             or the enumerate was incomplete.

        Connection errors propagate to the caller for reconnect handling.
        """
        if not panel_lookup:
            return

        log.debug("[%s] Panel enumerate cycle starting (%d known panel points)",
                  self.node_name, len(panel_lookup))
        t0 = time.monotonic()
        try:
            results = conn.enumerate_all_points(self.node_name.lower())
        except (BrokenPipeError, ConnectionResetError, OSError):
            raise
        except Exception as e:
            log.warning("[%s] Panel enumerate failed: %s — flagging "
                        "all panel points as comm-fault",
                        self.node_name, e)
            self._mark_panel_comm_failure(panel_lookup)
            return

        elapsed = time.monotonic() - t0

        # A dead socket does not reach the handler above. `enumerate_all_points`
        # catches its own send/recv failures, breaks its walk and returns an
        # EMPTY LIST -- so a connection that died mid-session looks like a panel
        # with nothing to say. An earlier edition took that at face value,
        # flagged every point comm-fault and carried on polling the corpse
        # forever: the points never recovered, because `run()` was never given
        # the chance to reconnect.
        #
        # We only get here with a non-empty `panel_lookup`, so the panel is
        # known to have points. Zero records back is therefore a broken
        # connection, not an empty panel. Raise into the caller's reconnect
        # path; `ConnectionError` is an `OSError`, which is what it catches.
        if not results:
            self._mark_panel_comm_failure(panel_lookup)
            raise ConnectionError(
                "panel enumerate returned no records for %d known panel points "
                "- treating the connection as dead" % len(panel_lookup))

        matched = 0
        seen_names = set()
        for r in results:
            if r.get("subkey"):
                continue
            if r.get("value") is None:
                continue
            pt_name = (r.get("point") or "").strip()
            if not pt_name:
                continue
            seen_names.add(pt_name)
            entry = panel_lookup.get(pt_name)
            if entry is None:
                continue

            # Synthesize a result dict shaped like read_point output so
            # update_from_read sees a clean live read.
            synthetic = {
                "value": r["value"],
                "units": r.get("units", ""),
                "comm_status": None,
            }
            self.total_reads += 1
            self.successful_reads += 1
            update = update_from_read(entry, synthetic)
            obj = self.objects.get(
                (entry.bacnet_object_type, entry.bacnet_instance))
            if obj is not None:
                apply_update(obj, update)
            matched += 1

        # Panel points not present in this enumerate get comm-fault'd
        missing = 0
        for name, entry in panel_lookup.items():
            if name not in seen_names:
                self.total_reads += 1
                self.failed_reads += 1
                update = update_from_read(entry, None)
                obj = self.objects.get(
                    (entry.bacnet_object_type, entry.bacnet_instance))
                if obj is not None:
                    apply_update(obj, update)
                missing += 1

        log.info("[%s] Panel enumerate: %d/%d matched, %d missing, %.1fs",
                 self.node_name, matched, len(panel_lookup), missing, elapsed)

    def _mark_panel_comm_failure(self,
                                 panel_lookup: Dict[str, PointEntry]) -> None:
        """Flag every panel-source object on this node with comm-fault."""
        update = ObjectUpdate(
            present_value=None,
            reliability=RELIABILITY_COMM_FAILURE,
            status_flags=STATUS_FLAGS_FAULT,
        )
        for entry in panel_lookup.values():
            obj = self.objects.get(
                (entry.bacnet_object_type, entry.bacnet_instance))
            if obj is not None:
                apply_update(obj, update)
