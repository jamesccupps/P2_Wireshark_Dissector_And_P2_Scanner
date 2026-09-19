#!/usr/bin/env python3
"""
p2_bacnet_bridge.py — P2-to-BACnet bridge runtime.

Reads APOGEE PXC controllers over P2 (TCP/5033), exposes every point as a
BACnet/IP object so any BACnet supervisor (Desigo CC, Niagara, EBI,
ENTELI-NET, etc.) can read them as native BACnet.

Read-only by design.

Quick start:

  1. Generate a manifest (one-time, walks your site):

       python tools/build_manifest.py \\
           --site site.json \\
           --bridge-config bridge_config.json \\
           --out manifest.json

  2. Run the bridge:

       python p2_bacnet_bridge.py \\
           --site site.json \\
           --bridge-config bridge_config.json \\
           --manifest manifest.json

The bridge depends on the P2 Scanner library (`p2_scanner.py` and
the TEC catalog it embeds). Place it on PYTHONPATH, beside this script, or
in the repository root with the bridge in `bridge/`.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import threading
import time
from collections import defaultdict
import re
from pathlib import Path
from typing import Dict, List

#: One logger for the whole entry module. Two functions used to bind this name
#: locally, so a helper added later referenced a `log` that did not exist --
#: caught by pyflakes, not by the tests.
log = logging.getLogger("bridge")

# The scanner is the bridge's P2 stack. p2_bridge.scanner_path knows which
# layouts it can live in -- repo sibling, standalone copy, or PYTHONPATH --
# and puts the right directory on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from p2_bridge.scanner_path import ensure_scanner_importable

try:
    ensure_scanner_importable()
    import p2_scanner  # type: ignore
except ImportError as e:
    sys.stderr.write(f"ERROR: {e}\n")
    sys.exit(2)

# Verify bacpypes3 is recent enough. The bridge uses
# Application.from_object_list() and the local.device / local.networkport
# import paths, all of which require bacpypes3 >= 0.0.100. Older versions
# fail with AttributeError or ImportError partway into BACnet app
# construction — under pythonw.exe (the GUI launcher) those errors go to
# stderr and disappear silently. Catch the version mismatch up front with
# a message that points at the actual fix.
try:
    import bacpypes3  # noqa: F401
    _bp3_version = getattr(bacpypes3, "__version__", "0.0.0")
    _major, _minor, _patch = (int(p) for p in _bp3_version.split(".")[:3])
    _bp3_ok = (_major, _minor, _patch) >= (0, 0, 100)
except Exception:
    _bp3_version = "?"
    _bp3_ok = False

if not _bp3_ok:
    msg = (
        f"ERROR: bacpypes3 version {_bp3_version} is too old. The bridge "
        "requires bacpypes3 >= 0.0.100 for the Application.from_object_list "
        "API and the local.device import path.\n\n"
        "Fix:\n"
        "    pip install --upgrade --force-reinstall \"bacpypes3>=0.0.100,<0.1\"\n\n"
        "If pip refuses because another package (commonly BAC0) is pinning "
        "an older version, the --force-reinstall flag overrides it. The "
        "bridge does not depend on BAC0 — only on bacpypes3 directly.\n"
    )
    sys.stderr.write(msg)
    # Also try logging in case stderr is invisible (pythonw.exe / GUI launcher)
    try:
        logging.basicConfig(level=logging.ERROR,
                            filename="p2_bacnet_bridge.log",
                            format="%(asctime)s [%(levelname)s] %(message)s")
        logging.error(msg.replace("\n", " | "))
    except OSError:
        pass       # read-only cwd; stderr above is the only channel left
    sys.exit(3)

from p2_bridge.config import BridgeConfig, SiteConfig, setup_logging
from p2_bridge.manifest import Manifest, PointEntry
from p2_bridge.bacnet_app import build_application, run_application
from p2_bridge.poller import NodePoller


def parse_args():
    p = argparse.ArgumentParser(
        description="P2-to-BACnet bridge — exposes APOGEE PXC points as BACnet/IP objects.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--site", default="site.json",
                   help="P2 site config (shared format with P2 Scanner)")
    p.add_argument("--bridge-config", default="bridge_config.json",
                   help="Bridge-specific config (BACnet identity, polling)")
    p.add_argument("--manifest", default="manifest.json",
                   help="Point manifest — generate first with tools/build_manifest.py")
    p.add_argument("--show-firmware", action="store_true",
                   help="Connect to every panel in site.known_nodes, read 0x010C "
                        "SystemInfo, and print the decoded firmware build. "
                        "Exits without starting the BACnet bridge — useful for "
                        "fleet inventory.")
    return p.parse_args()


def seed_firmware_registry(site: SiteConfig) -> None:
    """Prime the firmware build-tag cache from `site.known_builds`.

    So a panel already identified does not need a fresh `0x010C` read to name
    its firmware. A convenience, not a protocol requirement -- nothing about
    framing depends on the build tag (PROTOCOL.md §6.2).

    **This deliberately does not touch `p2_scanner`'s module globals.** An
    earlier edition set `P2_NETWORK`, `SCANNER_NAME` and `P2_SITE` here, which
    made every call into the scanner depend on hidden module state. Nothing on
    the bridge's runtime path needs it: `P2Connection` takes `network` and
    `scanner_name` as arguments, and both `NodePoller` and `_read_system_info`
    pass them. The two module-level functions that do read those globals --
    `enumerate_fln_devices` and `get_device_application` -- run only in
    `tools/build_manifest.py`, which sets them itself.
    """
    try:
        import firmware_registry
        firmware_registry.load_build_tags(site.known_builds)
        # B-5: log any cached build tags the registry doesn't recognize so
        # the operator can flag them for inclusion in the build registry.
        # A build tag the registry has no entry for. This used to ask
        # `negotiate_dialect(tag) is None`, which was a membership test wearing
        # a dialect lookup's clothes -- and the function is gone with the model.
        unknown = [
            (host, tag) for host, tag in (site.known_builds or {}).items()
            if tag not in firmware_registry.KNOWN_BUILDS
        ]
        for host, tag in unknown:
            classification = firmware_registry.classify_unknown_build(tag)
            log.warning(
                "Unknown firmware build tag %r at %s (heuristic: %s). "
                "Please report so it can be added to the build registry.",
                tag, host, classification,
            )
    except ImportError:
        pass  # firmware_registry missing — bridge falls back to dynamic detection


def group_by_node(points: List[PointEntry]) -> Dict[str, List[PointEntry]]:
    grouped: Dict[str, List[PointEntry]] = defaultdict(list)
    for pt in points:
        grouped[pt.node].append(pt)
    return grouped


def _validate_bacnet_config(cfg: BridgeConfig) -> None:
    """Validate BACnet identity values BEFORE we hand them to bacpypes3.

    bacpypes3's primitive type casts produce terse errors like 'instance
    out of range' that don't tell you which field was wrong or what the
    legal range is. This pre-flight check fails with an actionable message
    that points at the specific field in bridge_config.json.

    BACnet field ranges (per ASHRAE 135):
      - device instance: unsigned 22-bit  (0 to 4194302; 4194303 reserved)
      - vendor id:       unsigned 16-bit  (0 to 65535)
    """
    errors: list[str] = []

    if not (0 <= cfg.bacnet_device_instance <= 4194302):
        errors.append(
            f"bacnet_device_instance={cfg.bacnet_device_instance} is out "
            f"of range. Must be 0 to 4194302 (BACnet 22-bit instance limit). "
            f"Common convention is to pick a unique number in your site's "
            f"reserved BACnet range, e.g. 599001."
        )

    if not (0 <= cfg.bacnet_vendor_identifier <= 65535):
        errors.append(
            f"bacnet_vendor_identifier={cfg.bacnet_vendor_identifier} is "
            f"out of range. Must be 0 to 65535 (16-bit). Vendor 999 is the "
            f"test/example range; register a real ID with ASHRAE for "
            f"production deployments."
        )

    # Required string fields
    if not (cfg.bacnet_device_name or "").strip():
        errors.append("bacnet_device_name is empty.")
    addr = (cfg.bacnet_address or "").strip()
    if not addr:
        errors.append(
            "bacnet_address is empty. Use the form IP/PREFIX:PORT, e.g. "
            "192.168.1.50/24:47808 or 0.0.0.0/24:47808 to bind every "
            "interface."
        )
    else:
        # Format check: IP/PREFIX:PORT. Catches transposed segments like
        # "192.168.1.50:47808/24" before bacpypes3 gives a terse error.
        m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})"
                     r":(\d{1,5})$", addr)
        if not m:
            errors.append(
                f"bacnet_address={addr!r} is malformed. Expected "
                "IP/PREFIX:PORT (e.g. 192.168.1.50/24:47808). Got a "
                "string that doesn't match — common cause is "
                "transposed prefix and port (.50:47808/24)."
            )
        else:
            ip_parts = [int(p) for p in m.group(1).split('.')]
            prefix = int(m.group(2))
            port = int(m.group(3))
            if any(not (0 <= p <= 255) for p in ip_parts):
                errors.append(
                    f"bacnet_address has an out-of-range octet in IP "
                    f"{m.group(1)} (each octet must be 0-255).")
            if not (0 <= prefix <= 32):
                errors.append(
                    f"bacnet_address prefix /{prefix} is out of range "
                    "(must be 0-32). /24 is the typical BAS-VLAN value.")
            if not (1 <= port <= 65535):
                errors.append(
                    f"bacnet_address port :{port} is out of range "
                    "(must be 1-65535). 47808 is the BACnet/IP default.")

    if errors:
        msg = "ERROR: bridge_config.json has invalid BACnet values:\n"
        for e in errors:
            msg += f"  - {e}\n"
        msg += "\nFix the values in bridge_config.json and restart.\n"
        raise ValueError(msg)


def _reload_bridge_config(cfg_path: Path, current_cfg: BridgeConfig,
                          log: logging.Logger) -> None:
    """Re-read bridge_config.json and update reload-safe fields in place.

    Triggered by SIGHUP on Unix. The bridge config is a mutable dataclass
    and NodePoller reads ``self.cfg.XXX`` per iteration, so a live mutation
    is picked up within one polling cycle. We only touch fields that are
    safe to change without tearing down BACnet sessions or BACnet object
    bindings.

    Reload-safe (changeable without restart):
      - poll intervals, inter-read delay, poll jitter
      - panel-enumerate interval
      - reconnect backoff (used on next disconnect)
      - log level

    NOT reload-safe (require restart):
      - bacnet_device_instance / device_name / vendor_identifier
      - bacnet_address (network binding)
      - instance_id_start, log_file path, log rotation caps
      - firmware/application revision (BACnet object properties)
    """
    if not cfg_path.exists():
        log.error("SIGHUP: bridge config not found at %s", cfg_path)
        return
    try:
        new_cfg = BridgeConfig.from_file(cfg_path)
    except Exception as e:
        log.error("SIGHUP: failed to parse %s: %s", cfg_path, e)
        return

    reloadable = [
        "default_poll_interval_s", "digital_poll_interval_s",
        "inter_read_delay_s", "poll_jitter_s",
        "panel_enumerate_interval_s",
        "reconnect_backoff_initial_s", "reconnect_backoff_max_s",
        "log_level",
    ]
    changed: list[tuple[str, object, object]] = []
    for field_name in reloadable:
        old_val = getattr(current_cfg, field_name)
        new_val = getattr(new_cfg, field_name)
        if old_val != new_val:
            setattr(current_cfg, field_name, new_val)
            changed.append((field_name, old_val, new_val))

    # Apply log-level change live.
    if any(name == "log_level" for name, *_ in changed):
        new_level = getattr(logging, current_cfg.log_level.upper(), logging.INFO)
        logging.getLogger().setLevel(new_level)

    if changed:
        log.info("SIGHUP: reloaded %d field(s) from %s", len(changed), cfg_path)
        for name, old, new in changed:
            log.info("  %s: %r -> %r", name, old, new)
    else:
        log.info("SIGHUP: no reloadable fields changed in %s", cfg_path)


def _read_system_info(site: SiteConfig, node_name: str, host: str):
    """Read `0x010C` SystemInfo from one panel. Returns (info, fail_reason).

    `read_system_info_compact` is a `P2Connection` method, not a module
    function; an earlier edition called it as `p2_scanner.read_system_info_compact`
    and the resulting AttributeError was swallowed by a broad handler and
    reported as an unreachable panel.

    The connection is given `network` and `scanner_name` explicitly, the same
    way `NodePoller` does, rather than relying on module globals.
    """
    conn = None
    try:
        conn = p2_scanner.P2Connection(
            host,
            network=site.p2_network,
            scanner_name=site.scanner_name,
        )
        if not conn.connect(node_name.lower()):
            return None, "handshake refused"
        info = conn.read_system_info_compact(node_name.lower())
        return info, ("" if info else "no response")
    except OSError as e:
        return None, f"{type(e).__name__}: {e}"
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError as e:
                log.debug("[%s] error closing connection: %s", node_name, e)


def _run_show_firmware(site: SiteConfig) -> int:
    """Print decoded firmware info for every panel in site.known_nodes.

    Opens a P2Connection per panel and calls its `read_system_info_compact`
    (which speaks `0x010C`), then `firmware_registry.describe_build` for the
    human-readable summary. Returns 0 if every panel responded, 1 if any failed.
    """
    try:
        import firmware_registry
    except ImportError:
        sys.stderr.write("ERROR: firmware_registry module not available\n")
        return 2

    if not site.known_nodes:
        sys.stderr.write("No nodes in site config — nothing to inventory.\n")
        return 0

    seed_firmware_registry(site)

    print(f"\nFleet firmware inventory — {len(site.known_nodes)} node(s)")
    print("=" * 72)
    print(f"{'node':<16} {'host':<16} {'build':<10} description")
    print("-" * 72)

    failed = 0
    for node_name in sorted(site.known_nodes.keys()):
        host = site.known_nodes[node_name]
        # Prefer cached tag (no network round-trip) if available; otherwise
        # do a live 0x010C read.
        tag = firmware_registry.get_cached_build_tag(host)
        if tag is None:
            info, fail_reason = _read_system_info(site, node_name, host)
            if info:
                tag = firmware_registry.parse_build_tag(info.get('model'))
            else:
                print(f"{node_name:<16} {host:<16} {'':<10} [FAIL] {fail_reason}")
                failed += 1
                continue

        if tag is None:
            print(f"{node_name:<16} {host:<16} {'?':<10} "
                  f"[WARN] no build-tag TLV in response")
            failed += 1
            continue

        print(f"{node_name:<16} {host:<16} {tag:<10} "
              f"{firmware_registry.describe_build(tag)}")

    print()
    return 0 if failed == 0 else 1


def main() -> int:
    args = parse_args()

    # Load configs
    bridge_cfg_path = Path(args.bridge_config)
    site_cfg_path = Path(args.site)
    manifest_path = Path(args.manifest)

    if not bridge_cfg_path.exists():
        sys.stderr.write(f"ERROR: bridge config not found: {bridge_cfg_path}\n")
        return 2
    if not site_cfg_path.exists():
        sys.stderr.write(f"ERROR: site config not found: {site_cfg_path}\n")
        return 2
    if not manifest_path.exists():
        sys.stderr.write(
            f"ERROR: manifest not found: {manifest_path}\n"
            "Generate one first with tools/build_manifest.py\n"
        )
        return 2

    bridge_cfg = BridgeConfig.from_file(bridge_cfg_path)
    site_cfg = SiteConfig.from_file(site_cfg_path)
    setup_logging(bridge_cfg)


    # B-4: --show-firmware short-circuits before BACnet startup. Connects
    # to every node, reads 0x010C SystemInfo and prints the decoded build
    # info. Useful for fleet inventory and for catching panels whose build
    # tag isn't in firmware_registry.KNOWN_BUILDS.
    if args.show_firmware:
        return _run_show_firmware(site_cfg)

    # Validate BACnet identity values up front. Catches range errors with
    # a clear message before we hand them to bacpypes3 (which raises
    # terse 'instance out of range' / 'invalid vendor' errors that don't
    # point at the field).
    try:
        _validate_bacnet_config(bridge_cfg)
    except ValueError as e:
        log.error(str(e))
        sys.stderr.write(str(e))
        return 4

    log.info("p2-bacnet-bridge starting")
    log.info("  site: %s", site_cfg_path)
    log.info("  bridge config: %s", bridge_cfg_path)
    log.info("  manifest: %s", manifest_path)
    log.info("  P2 network: %s", site_cfg.p2_network)
    log.info("  P2 nodes: %d", len(site_cfg.known_nodes))

    seed_firmware_registry(site_cfg)
    manifest = Manifest.load(manifest_path)
    log.info("  manifest points: %d", len(manifest.points))

    # Sanity-check: every manifest node must be in site.known_nodes
    nodes_in_manifest = {p.node for p in manifest.points}
    nodes_in_site = set(site_cfg.known_nodes.keys())
    missing = nodes_in_manifest - nodes_in_site
    if missing:
        log.warning("Manifest references nodes not in site config: %s",
                    sorted(missing))
        log.warning("Points on those nodes will be excluded.")

    # Pollers are started AFTER the BACnet app comes up — see on_started below.
    stop_event = threading.Event()
    pollers: List[NodePoller] = []

    def on_app_started(app, objects_by_id, active_entries):
        """Called from inside the asyncio loop once the BACnet app is bound."""
        grouped = group_by_node(active_entries)
        for node_name, node_points in grouped.items():
            host = site_cfg.known_nodes.get(node_name)
            if not host:
                log.warning("Skipping node %s — no host in site config", node_name)
                continue
            poller = NodePoller(
                node_name=node_name,
                host=host,
                site=site_cfg,
                cfg=bridge_cfg,
                points=node_points,
                objects=objects_by_id,
                stop_event=stop_event,
                scanner_module=p2_scanner,
            )
            pollers.append(poller)
            poller.start()
            log.info("Started poller for %s (%s) — %d points",
                     node_name, host, len(node_points))

    # Run the asyncio event loop. The BACnet app is built INSIDE the loop
    # (bacpypes3 binds its UDP socket via asyncio.get_running_loop() during
    # construction, so it must run from inside a running loop).
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    async_stop = asyncio.Event()

    # Filter out noise from malformed BACnet frames sent by other devices
    # on the network. In real-world multi-vendor BACnet/IP networks, foreign
    # devices routinely send broadcast frames whose encoding doesn't match
    # bacpypes3's strict decoder — InvalidTag, DecodingError, etc. These
    # are not bridge bugs and they don't affect bridge operation; they're
    # just packets we couldn't process. Without this filter, every such
    # packet generates an "asyncio: Task exception was never retrieved"
    # traceback that drowns the real log output.
    foreign_frame_count = {"n": 0}

    def asyncio_exception_handler(loop, context):
        exc = context.get("exception")
        # Lazy-import bacpypes3 errors so this works even if names move
        # between bacpypes3 versions.
        try:
            from bacpypes3.errors import InvalidTag, DecodingError, RejectException
            ignorable = (InvalidTag, DecodingError, RejectException)
        except ImportError:
            ignorable = ()

        if exc is not None and isinstance(exc, ignorable):
            foreign_frame_count["n"] += 1
            # Log once per 50 to confirm it's still happening, otherwise stay quiet
            if foreign_frame_count["n"] == 1 or foreign_frame_count["n"] % 50 == 0:
                log.debug("Ignored %d malformed BACnet frame(s) from foreign "
                          "devices on the network (latest: %s)",
                          foreign_frame_count["n"], exc)
            return
        # Anything else — let asyncio handle it normally
        loop.default_exception_handler(context)

    loop.set_exception_handler(asyncio_exception_handler)

    def request_shutdown(signum, _frame):
        log.info("Received signal %d — initiating shutdown", signum)
        loop.call_soon_threadsafe(async_stop.set)

    signal.signal(signal.SIGINT, request_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_shutdown)
    # SIGHUP triggers a live config reload (Unix only — Windows has no
    # SIGHUP). Only reload-safe fields are updated; see _reload_bridge_config
    # for the list. Operators tune polling cadence / log level without
    # paying the cost of a full restart.
    if hasattr(signal, "SIGHUP"):
        def sighup_handler(signum, _frame):
            log.info("SIGHUP received — reloading %s", bridge_cfg_path)
            _reload_bridge_config(bridge_cfg_path, bridge_cfg, log)
        signal.signal(signal.SIGHUP, sighup_handler)

    def app_builder():
        return build_application(bridge_cfg, manifest)

    async def heartbeat_task():
        """Log per-poller progress every 30s so the operator can see the
        bridge is alive even during long polling cycles."""
        while not async_stop.is_set():
            try:
                await asyncio.wait_for(async_stop.wait(), timeout=30.0)
                return
            except asyncio.TimeoutError:
                pass
            for p in pollers:
                if p.connection_state == "connected":
                    n_pts = max(1, len([e for e in p.points if e.enabled]))
                    cycle_n = p.total_reads // n_pts + 1
                    pct = (p.total_reads % n_pts) * 100.0 / n_pts
                    log.info("[%s] heartbeat — cycle %d, %.0f%% through "
                             "(reads=%d success=%d fail=%d)",
                             p.node_name, cycle_n, pct,
                             p.total_reads, p.successful_reads, p.failed_reads)
                else:
                    age = time.time() - (p.last_connect_attempt_at or time.time())
                    log.info("[%s] heartbeat — state=%s, last connect "
                             "attempt %.0fs ago",
                             p.node_name, p.connection_state, age)

    async def main_coro():
        # Run the application and the heartbeat together
        hb = asyncio.create_task(heartbeat_task())
        try:
            await run_application(app_builder, async_stop, on_started=on_app_started)
        finally:
            hb.cancel()
            try:
                await hb
            except (asyncio.CancelledError, Exception):
                pass

    try:
        loop.run_until_complete(main_coro())
    except Exception as exc:
        # Without this, an exception during BACnet app construction or
        # asyncio loop execution prints to stderr and disappears when the
        # bridge is launched via pythonw.exe (no console). Log it through
        # the logging module so it lands in p2_bacnet_bridge.log where
        # the operator can actually see it.
        log.exception("Bridge crashed: %s", exc)
        log.error("If this is a BACnet bind error, check that "
                  "'bacnet_address' in bridge_config.json points to a real "
                  "interface IP on this host. Use 0.0.0.0/24:47808 to bind "
                  "every interface as a quick test.")
        return 1
    finally:
        log.info("Stopping pollers")
        stop_event.set()
        deadline = time.time() + 10.0
        for poller in pollers:
            remaining = deadline - time.time()
            if remaining > 0:
                poller.join(timeout=remaining)
        log.info("Shutdown complete")
        loop.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
